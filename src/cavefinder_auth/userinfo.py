"""Live `/api/userinfo` client with in-process TTL cache.

Phase 1 of the cave-id admin-panel consolidation makes cave-id the
single source of truth for tier across cavefinder / georef / surveylens.
Client apps drop their local ``users.tier`` column and call this helper
instead. The trade-off vs. reading the JWT claim:

  - JWT ``tier`` is up to 15 minutes stale (the access-token lifetime).
    A user who upgrades to Pro waits up to 15 min before paywalled
    features unlock.
  - This helper hits cave-id's ``/api/userinfo`` and surfaces the live
    tier on the next request — the bound becomes the cache TTL (default
    60 s), or zero if the caller passes ``ttl_seconds=0``.

The cache is keyed by ``(user_id, access_token_prefix)`` so two users
sharing the same machine never see each other's tier, and a re-issued
token (post-refresh) cleanly misses cache. Token-prefix only — never
the full token — so a memory dump can't replay the bearer.

# Failure mode

Network or non-2xx falls back to the JWT claim. That's ≤ 15 min stale,
which is strictly better than the alternative (every request errors
out when cave-id is briefly down). Logs the failure once per cache
window.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 60.0
DEFAULT_TIMEOUT_SECONDS = 3.0


@dataclass
class _CacheEntry:
    expires_at: float
    payload: dict[str, Any]


class UserinfoClient:
    """Fetches `/api/userinfo` from cave-id with a per-(user, token) cache.

    Construct one per app process — the cache is in-memory and shared
    across all coroutines on this process. For multi-worker deployments
    each worker has its own cache; that's intentional, the staleness
    bound is still ``ttl_seconds``.

    ``base_url`` should be the IdP origin (``https://id.cavefinder.app``).
    No trailing path — this client appends ``/api/userinfo`` itself.
    """

    def __init__(
        self,
        base_url: str,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        client_factory=None,
        cookie_name: str = "__Secure-cf_at",
    ) -> None:
        if not base_url:
            raise ValueError("UserinfoClient requires a non-empty base_url")
        self._base_url = base_url.rstrip("/")
        self._ttl = float(ttl_seconds)
        self._timeout = float(timeout_seconds)
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(timeout=timeout_seconds)
        )
        self._cookie_name = cookie_name
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _token_prefix(access_token: str) -> str:
        # SHA-256 prefix — short enough to be cheap to hash, long
        # enough to make per-token cache entries collide-free in
        # practice. Never the raw token: a memory dump or log bleed
        # then can't replay.
        return hashlib.sha256(access_token.encode("ascii", "ignore")).hexdigest()[:16]

    def _cache_key(self, user_id: int, access_token: str) -> str:
        return f"{user_id}:{self._token_prefix(access_token)}"

    def _claims_fallback(self, claims: dict[str, Any]) -> dict[str, Any]:
        """Synthesize a userinfo-shaped dict from JWT claims for the
        cave-id-down failure path. ``tier_expires_at`` isn't in the
        token, so callers see None and behave as if there's no expiry —
        same as before Phase 1, never worse.
        """
        return {
            "id": int(claims.get("sub") or claims.get("user_id") or 0),
            "email": claims.get("email"),
            "display_name": claims.get("display_name"),
            "tier": claims.get("tier") or "free",
            "tier_expires_at": None,
            "email_verified": claims.get("email_verified", False),
            "is_admin": claims.get("is_admin", False),
            "impersonator_id": claims.get("imp"),
        }

    async def fetch(
        self,
        *,
        access_token: str,
        claims: dict[str, Any],
        ttl_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Return a userinfo dict — cached, or freshly fetched, or
        falled back to the JWT claims on cave-id failure.

        ``claims`` is the verified-and-decoded JWT. We need it to
        synthesize the fallback when cave-id is unreachable AND to
        identify the user_id (for the cache key).

        ``ttl_seconds`` overrides the per-call cache TTL. Pass 0 to
        force a fresh fetch ignoring the cache; the result is still
        written back so subsequent callers benefit.
        """
        ttl = self._ttl if ttl_seconds is None else float(ttl_seconds)
        try:
            user_id = int(claims["sub"])
        except (KeyError, TypeError, ValueError):
            return self._claims_fallback(claims)
        key = self._cache_key(user_id, access_token)

        # Single-flight: if many concurrent requests on this process
        # all want the same userinfo and the cache is cold, only one
        # of them does the fetch. Lock-then-recheck is the canonical
        # async pattern.
        now = time.time()
        if ttl > 0:
            entry = self._cache.get(key)
            if entry is not None and entry.expires_at > now:
                return entry.payload

        async with self._lock:
            if ttl > 0:
                entry = self._cache.get(key)
                if entry is not None and entry.expires_at > now:
                    return entry.payload

            payload = await self._http_fetch(access_token=access_token)
            if payload is None:
                return self._claims_fallback(claims)
            self._cache[key] = _CacheEntry(
                expires_at=time.time() + ttl, payload=payload,
            )
            return payload

    async def _http_fetch(self, *, access_token: str) -> dict[str, Any] | None:
        url = f"{self._base_url}/api/userinfo"
        # Send the access token both as a Cookie (cave-id reads
        # ``request.cookies[__Secure-cf_at]``) AND as an Authorization
        # bearer for callers that prefer header-based propagation.
        # cave-id today only checks the cookie; the bearer header is
        # forward-compat for a possible future header-auth path.
        headers = {
            "Cookie": f"{self._cookie_name}={access_token}",
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "cavefinder-auth-python/userinfo",
        }
        try:
            async with self._client_factory() as client:
                resp = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            log.warning(
                "userinfo.http_error",
                extra={"error_class": type(exc).__name__, "error": str(exc)},
            )
            return None
        if resp.status_code != 200:
            log.warning(
                "userinfo.non_200",
                extra={"status": resp.status_code, "body": resp.text[:200]},
            )
            return None
        try:
            return resp.json()
        except ValueError as exc:
            log.warning("userinfo.invalid_json", extra={"error": str(exc)})
            return None

    def invalidate(self, user_id: int) -> None:
        """Drop every cached entry for a given user_id (every token).

        Useful for logout flows that want the next request to round-trip
        cave-id rather than serve a stale cached row. Cheap — small
        in-memory dict scan.
        """
        prefix = f"{user_id}:"
        for k in list(self._cache.keys()):
            if k.startswith(prefix):
                del self._cache[k]


async def get_user_tier(
    client: UserinfoClient,
    *,
    access_token: str,
    claims: dict[str, Any],
) -> str:
    """Convenience: return just the live tier string. Wraps `client.fetch`.

    Always returns a string (defaults to ``"free"`` if the response is
    missing the field for some reason). Callers that want the full
    userinfo dict should use ``client.fetch(...)`` directly.
    """
    payload = await client.fetch(access_token=access_token, claims=claims)
    return payload.get("tier") or "free"
