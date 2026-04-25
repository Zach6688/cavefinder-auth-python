"""JWKS fetch + in-memory cache with stale-if-error.

DESIGN.md §6.1:
    Fetch JWKS from https://id.cavefinder.app/.well-known/jwks.json (cached 1 hour).
    Stale-if-error: on fetch failure, keep using the last-good key up to 24 hours
    and log a warning. Prevents IdP outages from nuking every client app.

The cache is an in-memory dict keyed by JWKS URL, so a single process shares one
copy across all requests. Thread-safe via a single ``threading.Lock`` — fine for
the typical uvicorn worker model (one event loop per process; lock contention is
negligible since we only touch it on JWKS refresh).
"""
from __future__ import annotations

import base64
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from .errors import JWKSFetchError

log = logging.getLogger(__name__)


@dataclass
class _CacheEntry:
    keys_by_kid: dict[str, RSAPublicKey]
    fetched_at: float


class JWKSCache:
    """Fetches + caches JWKS per URL. Reusable across AuthConfig instances.

    ``unknown_kid_ttl`` (default 10 s) is the negative-cache window. When a
    token arrives with a kid we didn't find after a forced refresh, we
    remember that "kid X wasn't here at time T" and reject subsequent
    tokens with the same kid for ``unknown_kid_ttl`` seconds without
    hitting the JWKS endpoint again. Closes the amplification vector
    documented in docs/AUTH_PACKAGE_REVIEW.md (OBS-1): without this, an
    attacker blasting random kids can turn every failed verification into
    a JWKS HTTP round-trip. 10 s is short enough that a real rotation
    lands quickly (and the refresh-on-unknown-kid path still runs on the
    first instance) and long enough to neutralize a tight loop.
    """

    def __init__(
        self,
        *,
        cache_ttl: int = 3600,
        stale_ttl: int = 86400,
        http_timeout: float = 5.0,
        unknown_kid_ttl: float = 10.0,
    ) -> None:
        self.cache_ttl = cache_ttl
        self.stale_ttl = stale_ttl
        self.http_timeout = http_timeout
        self.unknown_kid_ttl = unknown_kid_ttl
        self._entries: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()
        # Overridable for tests — see testing.override_jwks().
        self._overrides: dict[str, dict[str, RSAPublicKey]] = {}
        # Negative cache: (jwks_url → {kid → timestamp}) for kids we
        # looked up, did a forced refresh for, and still didn't find.
        # Scoped per-URL because a kid absent from one IdP might be
        # present at another.
        self._unknown_kids: dict[str, dict[str, float]] = {}

    # ──────────────────────────────────────────────────────────────
    # Test overrides
    # ──────────────────────────────────────────────────────────────
    def set_override(self, jwks_url: str, keys_by_kid: dict[str, RSAPublicKey]) -> None:
        """Testing hook — short-circuits HTTP fetch for this URL."""
        with self._lock:
            self._overrides[jwks_url] = dict(keys_by_kid)

    def clear_override(self, jwks_url: str) -> None:
        with self._lock:
            self._overrides.pop(jwks_url, None)

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────
    def get_key(self, jwks_url: str, kid: str) -> RSAPublicKey:
        """Return the RSA public key for ``kid``, refreshing the cache if needed.

        Cache semantics:
          * fresh (age ≤ cache_ttl): return from cache.
          * stale (cache_ttl < age ≤ stale_ttl): try refresh, fall back to cached
            value on any error (logged as WARNING).
          * expired (age > stale_ttl): must refresh; raise JWKSFetchError on failure.
          * missing (no cache at all): must refresh; raise JWKSFetchError on failure.

        If the key is still missing after a fresh fetch, raise JWKSFetchError —
        the caller treats that as an invalid token (wrong kid).
        """
        override = self._overrides.get(jwks_url)
        if override is not None:
            if kid in override:
                return override[kid]
            raise JWKSFetchError(f"kid {kid!r} not in JWKS override for {jwks_url}")

        now = time.time()

        # Negative cache — short-circuit before we touch the network.
        # A kid we just learned is absent stays absent for unknown_kid_ttl
        # seconds; repeated lookups can't amplify into JWKS traffic.
        neg = self._unknown_kids.get(jwks_url, {})
        neg_ts = neg.get(kid)
        if neg_ts is not None and (now - neg_ts) <= self.unknown_kid_ttl:
            raise JWKSFetchError(
                f"kid {kid!r} not found in JWKS at {jwks_url} "
                f"(negative-cached for {self.unknown_kid_ttl}s)"
            )

        entry = self._entries.get(jwks_url)

        need_fetch = entry is None or (now - entry.fetched_at) > self.cache_ttl

        if need_fetch:
            try:
                fetched = self._fetch(jwks_url)
                with self._lock:
                    self._entries[jwks_url] = _CacheEntry(
                        keys_by_kid=fetched, fetched_at=now
                    )
                entry = self._entries[jwks_url]
            except Exception as exc:
                if entry is not None and (now - entry.fetched_at) <= self.stale_ttl:
                    log.warning(
                        "JWKS fetch failed for %s — serving stale cache (%.0fs old): %s",
                        jwks_url,
                        now - entry.fetched_at,
                        exc,
                    )
                else:
                    raise JWKSFetchError(f"JWKS fetch failed for {jwks_url}: {exc}") from exc

        assert entry is not None  # for type narrowing; the branches above guarantee it
        key = entry.keys_by_kid.get(kid)
        if key is None:
            # Unknown kid — it might be a new key we haven't picked up yet. Force a
            # refresh once before giving up. This prevents a new-key rotation from
            # causing cached clients to 401 for up to an hour.
            if not need_fetch:
                try:
                    fetched = self._fetch(jwks_url)
                    with self._lock:
                        self._entries[jwks_url] = _CacheEntry(
                            keys_by_kid=fetched, fetched_at=now
                        )
                    key = fetched.get(kid)
                except Exception as exc:
                    log.warning("JWKS refresh-on-unknown-kid failed for %s: %s", jwks_url, exc)
            if key is None:
                # Still absent after a forced refresh — remember so the
                # next hit with the same kid doesn't trigger another
                # fetch. See OBS-1 note at the class docstring.
                with self._lock:
                    self._unknown_kids.setdefault(jwks_url, {})[kid] = now
                raise JWKSFetchError(f"kid {kid!r} not found in JWKS at {jwks_url}")
        return key

    # ──────────────────────────────────────────────────────────────
    # Internals
    # ──────────────────────────────────────────────────────────────
    def _fetch(self, jwks_url: str) -> dict[str, RSAPublicKey]:
        with httpx.Client(timeout=self.http_timeout) as client:
            resp = client.get(jwks_url)
            resp.raise_for_status()
            payload = resp.json()
        return _parse_jwks(payload)


def _parse_jwks(payload: dict[str, Any]) -> dict[str, RSAPublicKey]:
    """Deserialize a JWKS document into kid → RSAPublicKey."""
    if not isinstance(payload, dict) or "keys" not in payload:
        raise ValueError("JWKS missing 'keys' array")
    out: dict[str, RSAPublicKey] = {}
    for jwk in payload["keys"]:
        kty = jwk.get("kty")
        if kty != "RSA":
            # Silently skip non-RSA keys — forward-compatible with future algorithms.
            continue
        kid = jwk.get("kid")
        n = jwk.get("n")
        e = jwk.get("e")
        if not (kid and n and e):
            continue
        try:
            pub_numbers = RSAPublicNumbers(e=_b64url_to_int(e), n=_b64url_to_int(n))
            out[kid] = pub_numbers.public_key()
        except Exception as exc:  # malformed key — log and skip
            log.warning("Skipping malformed JWK kid=%r: %s", kid, exc)
            continue
    if not out:
        raise ValueError("JWKS contained no usable RSA keys")
    return out


def _b64url_to_int(value: str) -> int:
    """Decode a JWK ``n`` / ``e`` field (base64url, unpadded) to a big int."""
    padded = value + "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")
