"""Tests for `cavefinder_auth.userinfo.UserinfoClient` (Phase 1).

The contract:
  - 2xx → returns the JSON payload, cached for ttl_seconds.
  - non-2xx / network error / invalid JSON → returns the JWT-claim
    fallback so the client app degrades to ≤15-min-stale tier instead
    of erroring out.
  - cache key is per-(user_id, token_prefix) so two users on the same
    process can't see each other's tier.
  - ttl_seconds=0 → no caching, always fresh.
  - invalidate(user_id) drops every entry for that user across tokens.
"""
from __future__ import annotations

import pytest

from cavefinder_auth import UserinfoClient, get_user_tier


class _StubResponse:
    def __init__(self, status_code: int, body):
        self.status_code = status_code
        self._body = body
        self.text = body if isinstance(body, str) else ""

    def json(self):
        if isinstance(self._body, dict):
            return self._body
        raise ValueError("not json")


class _StubClient:
    """httpx-shape stand-in. Records every GET so tests can assert
    on call count (single-flight, cache hits) and headers.

    The `responses` list is shared by reference across every stub the
    factory hands out — each call to `client_factory()` makes a fresh
    AsyncClient-shaped object but they all consume from the same FIFO
    queue, so a single test can sequence "first 500, then 200".
    """

    def __init__(self, responses):
        self._responses = responses
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, headers=None):
        self.calls.append({"url": url, "headers": headers})
        if not self._responses:
            raise RuntimeError("test ran out of canned responses")
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def _make_client(responses, *, ttl_seconds: float = 60.0) -> tuple[UserinfoClient, list[_StubClient]]:
    holders: list[_StubClient] = []

    def factory():
        c = _StubClient(responses)
        holders.append(c)
        return c

    return UserinfoClient(
        base_url="https://id.cavefinder.app",
        ttl_seconds=ttl_seconds,
        client_factory=factory,
    ), holders


_CLAIMS = {
    "sub": 42,
    "email": "u@x.com",
    "display_name": "U",
    "tier": "free",
    "email_verified": True,
    "is_admin": False,
}


@pytest.mark.asyncio
async def test_fetch_returns_live_payload_and_caches() -> None:
    payload = {**_CLAIMS, "tier": "pro", "tier_expires_at": 9_999_999_999.0}
    client, holders = _make_client([_StubResponse(200, payload)])

    out1 = await client.fetch(access_token="t1", claims=_CLAIMS)
    out2 = await client.fetch(access_token="t1", claims=_CLAIMS)

    assert out1 == payload
    assert out2 == payload
    # Only one HTTP call — second was a cache hit.
    assert len(holders) == 1
    assert len(holders[0].calls) == 1
    assert holders[0].calls[0]["url"] == "https://id.cavefinder.app/api/userinfo"
    # Both Cookie and Authorization headers were sent.
    h = holders[0].calls[0]["headers"]
    assert "__Secure-cf_at=t1" in h["Cookie"]
    assert h["Authorization"] == "Bearer t1"


@pytest.mark.asyncio
async def test_fetch_falls_back_to_claims_on_5xx() -> None:
    """cave-id returning 500 must NOT break the request — fall back to
    the JWT claim (≤15 min stale) instead. Result is NOT cached so the
    next request retries cave-id."""
    client, _ = _make_client([_StubResponse(500, "boom")])

    out = await client.fetch(access_token="t1", claims=_CLAIMS)
    assert out["tier"] == "free"  # from claims
    assert out["id"] == 42

    # Second call — cache MUST NOT serve the 500 fallback. We give
    # the client a second canned response and expect it to be used.
    client2, holders2 = _make_client([
        _StubResponse(500, "boom"),
        _StubResponse(200, {**_CLAIMS, "tier": "business",
                            "tier_expires_at": None}),
    ])
    fail = await client2.fetch(access_token="t1", claims=_CLAIMS)
    assert fail["tier"] == "free"
    succeed = await client2.fetch(access_token="t1", claims=_CLAIMS)
    assert succeed["tier"] == "business"
    # Two real HTTP calls happened — the failed one wasn't cached.
    total_calls = sum(len(h.calls) for h in holders2)
    assert total_calls == 2


@pytest.mark.asyncio
async def test_fetch_falls_back_on_network_error() -> None:
    import httpx
    client, _ = _make_client([httpx.ConnectError("dns down")])
    out = await client.fetch(access_token="t1", claims=_CLAIMS)
    # Synthesized from claims, never raises.
    assert out["tier"] == "free"
    assert out["email"] == "u@x.com"


@pytest.mark.asyncio
async def test_fetch_falls_back_on_invalid_json() -> None:
    client, _ = _make_client([_StubResponse(200, "<html>500</html>")])
    out = await client.fetch(access_token="t1", claims=_CLAIMS)
    assert out["tier"] == "free"


@pytest.mark.asyncio
async def test_cache_key_separates_users() -> None:
    """User A and user B must never share a cache slot, even on the
    same token (which shouldn't happen in practice but enforce by
    construction)."""
    payload_a = {**_CLAIMS, "sub": 1, "tier": "free", "tier_expires_at": None}
    payload_b = {**_CLAIMS, "sub": 2, "tier": "pro", "tier_expires_at": None}
    client, holders = _make_client([
        _StubResponse(200, payload_a),
        _StubResponse(200, payload_b),
    ])

    a = await client.fetch(
        access_token="t1", claims={**_CLAIMS, "sub": 1},
    )
    b = await client.fetch(
        access_token="t1", claims={**_CLAIMS, "sub": 2},
    )
    assert a["tier"] == "free"
    assert b["tier"] == "pro"
    # Two separate http calls — the cache didn't cross users.
    total_calls = sum(len(h.calls) for h in holders)
    assert total_calls == 2


@pytest.mark.asyncio
async def test_cache_key_separates_tokens_for_same_user() -> None:
    """A re-issued token (post-refresh) must not serve the previous
    token's cached payload — important for the re-login flow."""
    payload1 = {**_CLAIMS, "tier": "free", "tier_expires_at": None}
    payload2 = {**_CLAIMS, "tier": "pro", "tier_expires_at": None}
    client, holders = _make_client([
        _StubResponse(200, payload1),
        _StubResponse(200, payload2),
    ])

    a = await client.fetch(access_token="token-A", claims=_CLAIMS)
    b = await client.fetch(access_token="token-B", claims=_CLAIMS)
    assert a["tier"] == "free"
    assert b["tier"] == "pro"
    total_calls = sum(len(h.calls) for h in holders)
    assert total_calls == 2


@pytest.mark.asyncio
async def test_ttl_zero_skips_cache() -> None:
    """Passing ttl_seconds=0 forces a round-trip every call. Useful
    for force-refresh after an admin action that the user expects to
    see immediately (not 60 s from now)."""
    payload = {**_CLAIMS, "tier": "pro", "tier_expires_at": None}
    client, holders = _make_client([
        _StubResponse(200, payload),
        _StubResponse(200, payload),
        _StubResponse(200, payload),
    ])

    for _ in range(3):
        await client.fetch(access_token="t1", claims=_CLAIMS, ttl_seconds=0)

    total_calls = sum(len(h.calls) for h in holders)
    assert total_calls == 3


@pytest.mark.asyncio
async def test_invalidate_drops_every_token_for_user() -> None:
    """Logout / impersonation-end / admin-driven session-revoke want
    the next page load to round-trip rather than serve a stale row.
    invalidate() removes every cache entry for the given user_id
    across however many tokens have been seen."""
    payload = {**_CLAIMS, "tier": "free", "tier_expires_at": None}
    client, holders = _make_client([
        _StubResponse(200, payload),
        _StubResponse(200, payload),
        _StubResponse(200, {**payload, "tier": "pro"}),
        _StubResponse(200, {**payload, "tier": "pro"}),
    ])

    # Seed two cache entries for user 42 (different tokens).
    await client.fetch(access_token="A", claims=_CLAIMS)
    await client.fetch(access_token="B", claims=_CLAIMS)
    # Cache hits — no extra HTTP.
    await client.fetch(access_token="A", claims=_CLAIMS)
    await client.fetch(access_token="B", claims=_CLAIMS)
    assert sum(len(h.calls) for h in holders) == 2

    client.invalidate(user_id=42)

    out_a = await client.fetch(access_token="A", claims=_CLAIMS)
    out_b = await client.fetch(access_token="B", claims=_CLAIMS)
    assert out_a["tier"] == "pro"
    assert out_b["tier"] == "pro"
    # Two more network calls fired post-invalidate.
    assert sum(len(h.calls) for h in holders) == 4


@pytest.mark.asyncio
async def test_get_user_tier_returns_string() -> None:
    """Convenience wrapper returns just the tier string."""
    payload = {**_CLAIMS, "tier": "business", "tier_expires_at": None}
    client, _ = _make_client([_StubResponse(200, payload)])
    tier = await get_user_tier(client, access_token="t1", claims=_CLAIMS)
    assert tier == "business"


@pytest.mark.asyncio
async def test_get_user_tier_defaults_to_free_on_missing_field() -> None:
    """If cave-id returns a payload without `tier` (defensive), the
    convenience helper returns "free" rather than None or empty."""
    client, _ = _make_client([_StubResponse(200, {"id": 42, "email": "u@x.com"})])
    tier = await get_user_tier(client, access_token="t1", claims=_CLAIMS)
    assert tier == "free"


def test_constructor_rejects_empty_base_url() -> None:
    with pytest.raises(ValueError):
        UserinfoClient(base_url="")
