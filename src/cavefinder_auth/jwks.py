"""JWKS fetch + in-memory cache with stale-if-error.

DESIGN.md §6.1:
    Fetch JWKS from https://id.cavefinder.app/.well-known/jwks.json (cached 1 hour).
    Stale-if-error: on fetch failure, keep using the last-good key up to 24 hours
    and log a warning. Prevents IdP outages from nuking every client app.

The cache is an in-memory dict keyed by JWKS URL, so a single process shares one
copy across all requests. Thread-safe via a single ``threading.Lock`` — fine for
the typical uvicorn worker model (one event loop per process; lock contention is
negligible since we only touch it on JWKS refresh).

Two robustness invariants beyond the basic cache:

* **Bounded LRU.** The cache is capped at ``max_urls`` entries (default 8 —
  more than enough for a single client app that only ever points at one IdP,
  plus some headroom for tests that exercise multiple URLs). If ``jwks_url``
  is ever derived from request input via a refactor mistake the cache cannot
  grow without bound. On overflow the least-recently-used entry is evicted.

* **Coalesced concurrent fetches.** During a cold start or right after a TTL
  expiry, N simultaneous requests would all trigger N independent httpx
  GETs. The cache tracks per-URL "fetch in flight" state (``threading.Event``
  for the sync path, ``asyncio.Future`` for the async path); callers that
  arrive while a fetch is already running wait on it instead of duplicating
  work.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import threading
import time
from collections import OrderedDict
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
    """Fetches + caches JWKS per URL. Reusable across AuthConfig instances."""

    def __init__(
        self,
        *,
        cache_ttl: int = 3600,
        stale_ttl: int = 86400,
        http_timeout: float = 5.0,
        max_urls: int = 8,
    ) -> None:
        self.cache_ttl = cache_ttl
        self.stale_ttl = stale_ttl
        self.http_timeout = http_timeout
        if max_urls < 1:
            raise ValueError("max_urls must be >= 1")
        self.max_urls = max_urls
        # OrderedDict so we can do O(1) LRU eviction via move_to_end / popitem(last=False).
        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        # Overridable for tests — see testing.override_jwks().
        self._overrides: dict[str, dict[str, RSAPublicKey]] = {}
        # Coalescing state. The sync map's value is set when a fetch starts and
        # cleared when it ends; concurrent callers wait on the event. Async map
        # holds a future per URL; concurrent callers ``await`` the same future.
        # Both maps are mutated under self._lock.
        self._inflight_sync: dict[str, threading.Event] = {}
        self._inflight_async: dict[str, asyncio.Future[dict[str, RSAPublicKey]]] = {}

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
    # Internal cache bookkeeping
    # ──────────────────────────────────────────────────────────────
    def _store_entry(self, jwks_url: str, entry: _CacheEntry) -> None:
        """Insert/refresh an entry and enforce the LRU cap. Caller holds _lock."""
        self._entries[jwks_url] = entry
        self._entries.move_to_end(jwks_url)
        while len(self._entries) > self.max_urls:
            evicted_url, _ = self._entries.popitem(last=False)
            log.debug("JWKS cache evicted LRU entry: %s", evicted_url)

    def _touch_entry(self, jwks_url: str) -> None:
        """Mark this entry as most-recently-used. Caller holds _lock."""
        if jwks_url in self._entries:
            self._entries.move_to_end(jwks_url)

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
        with self._lock:
            override = self._overrides.get(jwks_url)
        if override is not None:
            if kid in override:
                return override[kid]
            raise JWKSFetchError(f"kid {kid!r} not in JWKS override for {jwks_url}")

        now = time.time()
        with self._lock:
            entry = self._entries.get(jwks_url)
            if entry is not None:
                self._touch_entry(jwks_url)

        need_fetch = entry is None or (now - entry.fetched_at) > self.cache_ttl

        if need_fetch:
            try:
                fetched = self._fetch_coalesced(jwks_url)
                with self._lock:
                    self._store_entry(jwks_url, _CacheEntry(keys_by_kid=fetched, fetched_at=now))
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
                    fetched = self._fetch_coalesced(jwks_url)
                    with self._lock:
                        self._store_entry(jwks_url, _CacheEntry(keys_by_kid=fetched, fetched_at=now))
                    key = fetched.get(kid)
                except Exception as exc:
                    log.warning("JWKS refresh-on-unknown-kid failed for %s: %s", jwks_url, exc)
            if key is None:
                raise JWKSFetchError(f"kid {kid!r} not found in JWKS at {jwks_url}")
        return key

    async def get_key_async(self, jwks_url: str, kid: str) -> RSAPublicKey:
        """Async mirror of :meth:`get_key` — non-blocking JWKS fetch.

        Use this from ASGI middleware / async request handlers. The sync
        :meth:`get_key` blocks the event loop for up to ``http_timeout`` seconds
        on JWKS server slowness; this version awaits an ``httpx.AsyncClient``
        fetch instead. Cache semantics and override behavior are identical.
        """
        with self._lock:
            override = self._overrides.get(jwks_url)
        if override is not None:
            if kid in override:
                return override[kid]
            raise JWKSFetchError(f"kid {kid!r} not in JWKS override for {jwks_url}")

        now = time.time()
        with self._lock:
            entry = self._entries.get(jwks_url)
            if entry is not None:
                self._touch_entry(jwks_url)

        need_fetch = entry is None or (now - entry.fetched_at) > self.cache_ttl

        if need_fetch:
            try:
                fetched = await self._fetch_coalesced_async(jwks_url)
                with self._lock:
                    self._store_entry(jwks_url, _CacheEntry(keys_by_kid=fetched, fetched_at=now))
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
                    fetched = await self._fetch_coalesced_async(jwks_url)
                    with self._lock:
                        self._store_entry(jwks_url, _CacheEntry(keys_by_kid=fetched, fetched_at=now))
                    key = fetched.get(kid)
                except Exception as exc:
                    log.warning("JWKS refresh-on-unknown-kid failed for %s: %s", jwks_url, exc)
            if key is None:
                raise JWKSFetchError(f"kid {kid!r} not found in JWKS at {jwks_url}")
        return key

    # ──────────────────────────────────────────────────────────────
    # Coalesced fetch helpers
    # ──────────────────────────────────────────────────────────────
    def _fetch_coalesced(self, jwks_url: str) -> dict[str, RSAPublicKey]:
        """Sync coalesced fetch — N concurrent callers do exactly one HTTP GET.

        First caller installs a ``threading.Event``, performs the fetch, then
        sets the event. Concurrent callers see the event in the in-flight map
        and wait on it. After the leader returns, all followers re-read the
        cache (which the leader just populated) and use that value. On failure
        the leader re-raises; followers raise a generic JWKSFetchError after
        the wait so they don't all log identical stack traces.
        """
        with self._lock:
            existing = self._inflight_sync.get(jwks_url)
            if existing is None:
                event = threading.Event()
                self._inflight_sync[jwks_url] = event
                is_leader = True
            else:
                event = existing
                is_leader = False

        if not is_leader:
            # Wait for the leader. Bounded by http_timeout + a small slack so a
            # wedged leader can't pin followers forever.
            event.wait(timeout=self.http_timeout + 1.0)
            with self._lock:
                entry = self._entries.get(jwks_url)
            if entry is None:
                raise JWKSFetchError(f"JWKS fetch coalesced wait did not yield cached entry for {jwks_url}")
            return dict(entry.keys_by_kid)

        try:
            return self._fetch(jwks_url)
        finally:
            with self._lock:
                # Only pop if we're still the registered leader (defensive — should always be).
                if self._inflight_sync.get(jwks_url) is event:
                    self._inflight_sync.pop(jwks_url, None)
            event.set()

    async def _fetch_coalesced_async(self, jwks_url: str) -> dict[str, RSAPublicKey]:
        """Async coalesced fetch — concurrent awaiters share one httpx GET.

        First awaiter creates a ``Future`` and registers it in the in-flight
        map, runs the HTTP fetch, then sets the future's result or exception.
        Subsequent awaiters return ``asyncio.shield(future)`` so a follower
        cancellation does not propagate into the leader's fetch.
        """
        loop = asyncio.get_running_loop()
        with self._lock:
            existing = self._inflight_async.get(jwks_url)
            if existing is None:
                future: asyncio.Future[dict[str, RSAPublicKey]] = loop.create_future()
                self._inflight_async[jwks_url] = future
                is_leader = True
            else:
                future = existing
                is_leader = False

        if not is_leader:
            # Shield so a follower being cancelled doesn't cancel the leader's fetch.
            return await asyncio.shield(future)

        try:
            result = await self._fetch_async(jwks_url)
        except BaseException as exc:
            with self._lock:
                if self._inflight_async.get(jwks_url) is future:
                    self._inflight_async.pop(jwks_url, None)
            if not future.done():
                future.set_exception(exc if isinstance(exc, Exception) else RuntimeError(str(exc)))
            raise
        else:
            with self._lock:
                if self._inflight_async.get(jwks_url) is future:
                    self._inflight_async.pop(jwks_url, None)
            if not future.done():
                future.set_result(result)
            return result

    # ──────────────────────────────────────────────────────────────
    # Internals
    # ──────────────────────────────────────────────────────────────
    def _fetch(self, jwks_url: str) -> dict[str, RSAPublicKey]:
        with httpx.Client(timeout=self.http_timeout) as client:
            resp = client.get(jwks_url)
            resp.raise_for_status()
            payload = resp.json()
        return _parse_jwks(payload)

    async def _fetch_async(self, jwks_url: str) -> dict[str, RSAPublicKey]:
        async with httpx.AsyncClient(timeout=self.http_timeout) as client:
            resp = await client.get(jwks_url)
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
