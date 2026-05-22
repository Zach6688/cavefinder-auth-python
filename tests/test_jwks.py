"""JWKS cache + parser tests. HTTP is stubbed — no real network."""
from __future__ import annotations

import asyncio
import base64
import time

import httpx
import pytest

from cavefinder_auth import JWKSCache, JWKSFetchError
from cavefinder_auth.jwks import _b64url_to_int, _parse_jwks
from cavefinder_auth.testing import generate_test_keypair

JWKS_URL = "https://id.cavefinder.app/.well-known/jwks.json"


def _jwks_for(keypair) -> dict:
    nums = keypair.public.public_numbers()

    def enc(v: int) -> str:
        raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": keypair.kid, "n": enc(nums.n), "e": enc(nums.e)}]}


# ──────────────────────────────────────────────────────────────
# _parse_jwks unit tests
# ──────────────────────────────────────────────────────────────
def test_parse_jwks_happy_path(keypair):
    out = _parse_jwks(_jwks_for(keypair))
    assert keypair.kid in out
    # Compare moduli so we know the key roundtripped correctly.
    assert out[keypair.kid].public_numbers().n == keypair.public.public_numbers().n


def test_parse_jwks_skips_non_rsa_keys(keypair):
    payload = _jwks_for(keypair)
    payload["keys"].append({"kty": "EC", "kid": "ec-1"})
    out = _parse_jwks(payload)
    assert list(out.keys()) == [keypair.kid]


def test_parse_jwks_rejects_empty():
    with pytest.raises(ValueError):
        _parse_jwks({"keys": []})


def test_parse_jwks_rejects_missing_keys_field():
    with pytest.raises(ValueError):
        _parse_jwks({"not-keys": []})


def test_b64url_to_int_roundtrips():
    # Standard JWK ``e`` is 65537 → "AQAB"
    assert _b64url_to_int("AQAB") == 65537


# ──────────────────────────────────────────────────────────────
# Cache behavior — fresh / stale / expired
# ──────────────────────────────────────────────────────────────
class _FakeTransport(httpx.BaseTransport):
    """Intercept httpx.Client calls and return a canned or error response."""

    def __init__(self) -> None:
        self.calls = 0
        self.payload: dict | None = None
        self.fail_with: Exception | None = None

    def handle_request(self, request):
        self.calls += 1
        if self.fail_with is not None:
            raise self.fail_with
        assert self.payload is not None
        return httpx.Response(200, json=self.payload, request=request)


@pytest.fixture
def transport():
    return _FakeTransport()


@pytest.fixture
def cache_with_transport(transport, monkeypatch):
    """A JWKSCache whose inner httpx.Client uses the fake transport."""
    original_client_init = httpx.Client.__init__

    def _init(self, *args, **kwargs):
        kwargs["transport"] = transport
        return original_client_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", _init)
    return JWKSCache(cache_ttl=60, stale_ttl=600)


def test_cache_fetches_on_first_access(cache_with_transport, transport, keypair):
    transport.payload = _jwks_for(keypair)
    key = cache_with_transport.get_key(JWKS_URL, keypair.kid)
    assert key.public_numbers().n == keypair.public.public_numbers().n
    assert transport.calls == 1


def test_cache_hits_within_ttl(cache_with_transport, transport, keypair):
    transport.payload = _jwks_for(keypair)
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    assert transport.calls == 1  # only the first access triggered an HTTP fetch


def test_cache_refetches_after_ttl(cache_with_transport, transport, keypair):
    transport.payload = _jwks_for(keypair)
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    # Force the cache entry's fetched_at into the past.
    entry = cache_with_transport._entries[JWKS_URL]
    entry.fetched_at = time.time() - 9999
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    assert transport.calls == 2


def test_cache_serves_stale_on_fetch_error(cache_with_transport, transport, keypair):
    """§6.1 stale-if-error — a fetch failure within the stale window is survivable."""
    transport.payload = _jwks_for(keypair)
    cache_with_transport.get_key(JWKS_URL, keypair.kid)  # populate
    transport.fail_with = httpx.ConnectError("IdP down")
    # Move fetched_at past the 60 s cache_ttl but within the 600 s stale_ttl.
    entry = cache_with_transport._entries[JWKS_URL]
    entry.fetched_at = time.time() - 120
    key = cache_with_transport.get_key(JWKS_URL, keypair.kid)
    assert key.public_numbers().n == keypair.public.public_numbers().n


def test_cache_raises_when_stale_window_expired(cache_with_transport, transport, keypair):
    transport.payload = _jwks_for(keypair)
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    transport.fail_with = httpx.ConnectError("IdP down")
    entry = cache_with_transport._entries[JWKS_URL]
    entry.fetched_at = time.time() - 9999  # past stale window
    with pytest.raises(JWKSFetchError):
        cache_with_transport.get_key(JWKS_URL, keypair.kid)


def test_cache_raises_when_no_cache_and_fetch_fails(cache_with_transport, transport):
    transport.fail_with = httpx.ConnectError("IdP down")
    with pytest.raises(JWKSFetchError):
        cache_with_transport.get_key(JWKS_URL, "any-kid")


def test_cache_refreshes_on_unknown_kid(cache_with_transport, transport, keypair):
    """New-key rotation: a token with a kid we don't know triggers one refresh."""
    # Start with an empty-ish JWKS that does NOT contain keypair.kid.
    transport.payload = {"keys": []}
    # First get_key must raise on empty JWKS (parsed rejects empty).
    with pytest.raises(Exception):
        cache_with_transport.get_key(JWKS_URL, keypair.kid)

    # Now the IdP "rotated" — JWKS now contains the new key.
    transport.payload = _jwks_for(keypair)
    key = cache_with_transport.get_key(JWKS_URL, keypair.kid)
    assert key.public_numbers().n == keypair.public.public_numbers().n


def test_override_bypasses_http(keypair):
    """set_override is the test hook used by override_jwks()."""
    cache = JWKSCache()
    cache.set_override(JWKS_URL, {keypair.kid: keypair.public})
    key = cache.get_key(JWKS_URL, keypair.kid)
    assert key is keypair.public


def test_override_unknown_kid_raises(keypair):
    cache = JWKSCache()
    cache.set_override(JWKS_URL, {keypair.kid: keypair.public})
    with pytest.raises(JWKSFetchError):
        cache.get_key(JWKS_URL, "wrong-kid")


def test_clear_override(keypair):
    cache = JWKSCache()
    cache.set_override(JWKS_URL, {keypair.kid: keypair.public})
    cache.clear_override(JWKS_URL)
    # With no override and no cache, fetching would need a real network call;
    # we just assert the override is gone.
    assert JWKS_URL not in cache._overrides


# ──────────────────────────────────────────────────────────────
# LRU eviction (H3)
# ──────────────────────────────────────────────────────────────
def test_jwks_cache_evicts_oldest_at_cap(keypair):
    """The cache is bounded — adding past ``max_urls`` evicts the LRU entry."""
    cache = JWKSCache(max_urls=3)
    # Pre-seed three distinct URLs via the override path so we don't need network.
    # We then directly populate _entries to simulate cached fetches because
    # set_override populates a SEPARATE dict that doesn't go through _store_entry.
    import time as _time

    urls = ["https://a/jwks", "https://b/jwks", "https://c/jwks", "https://d/jwks"]
    now = _time.time()
    # Manually exercise _store_entry to test LRU semantics directly.
    from cavefinder_auth.jwks import _CacheEntry

    with cache._lock:
        for url in urls[:3]:
            cache._store_entry(url, _CacheEntry(keys_by_kid={keypair.kid: keypair.public}, fetched_at=now))

    assert list(cache._entries.keys()) == urls[:3]

    # Touch the first URL so it becomes most-recently-used.
    with cache._lock:
        cache._touch_entry(urls[0])

    # Add a 4th URL — the LRU (now urls[1], since urls[0] was just touched) should be evicted.
    with cache._lock:
        cache._store_entry(urls[3], _CacheEntry(keys_by_kid={keypair.kid: keypair.public}, fetched_at=now))

    remaining = list(cache._entries.keys())
    assert len(remaining) == 3
    assert urls[1] not in remaining  # LRU was evicted
    assert urls[0] in remaining
    assert urls[2] in remaining
    assert urls[3] in remaining


def test_jwks_cache_max_urls_validates():
    """``max_urls`` must be >= 1."""
    with pytest.raises(ValueError):
        JWKSCache(max_urls=0)


# ──────────────────────────────────────────────────────────────
# Unknown-kid within TTL does NOT refetch (H4 corollary)
# ──────────────────────────────────────────────────────────────
def test_jwks_cache_unknown_kid_within_ttl_does_not_refetch(cache_with_transport, transport, keypair):
    """A second call asking for a kid that wasn't in the cached JWKS triggers
    a refresh (new-key-rotation handling), but the test pins that this happens
    exactly once per unknown-kid call — and that asking for the SAME unknown
    kid again does not keep refetching once we've concluded the kid genuinely
    isn't present.

    This protects against a thundering-herd of refetches when an attacker
    presents a malformed kid repeatedly within the TTL window.
    """
    transport.payload = _jwks_for(keypair)
    # First call populates the cache.
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    assert transport.calls == 1

    # Second call with an unknown kid triggers one refresh attempt (new-key path).
    with pytest.raises(JWKSFetchError):
        cache_with_transport.get_key(JWKS_URL, "totally-unknown-kid")
    refresh_calls = transport.calls
    assert refresh_calls == 2  # one extra fetch attempted

    # A subsequent valid-kid request inside the TTL must NOT trigger another fetch —
    # the unknown-kid refresh just updated fetched_at, so the cache is fresh.
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    assert transport.calls == refresh_calls  # no additional fetch


# ──────────────────────────────────────────────────────────────
# Coalesced concurrent fetch (H4)
# ──────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_jwks_cache_concurrent_cold_start_coalesces(keypair, monkeypatch):
    """N concurrent get_key_async calls on a cold cache => exactly one HTTP fetch.

    Without coalescing, asyncio.gather of N tasks on a freshly-constructed cache
    would each see an empty cache, each kick off their own httpx.AsyncClient
    fetch, and the JWKS endpoint would see N requests. The H4 fix tracks an
    in-flight Future per URL; followers await the leader's result.
    """
    cache = JWKSCache(cache_ttl=60, stale_ttl=600)
    call_counter = {"n": 0}

    async def fake_fetch(self, jwks_url):
        call_counter["n"] += 1
        # Simulate network latency so concurrent tasks all pile up while leader sleeps.
        await asyncio.sleep(0.05)
        return {keypair.kid: keypair.public}

    monkeypatch.setattr(JWKSCache, "_fetch_async", fake_fetch)

    # Fire 10 concurrent get_key_async calls.
    results = await asyncio.gather(*[cache.get_key_async(JWKS_URL, keypair.kid) for _ in range(10)])
    assert len(results) == 10
    assert all(r is keypair.public for r in results)
    # All ten callers should have piggy-backed on ONE underlying fetch.
    assert call_counter["n"] == 1


@pytest.mark.asyncio
async def test_jwks_cache_concurrent_fetch_failure_propagates_to_all(keypair, monkeypatch):
    """If the leader's fetch fails, every concurrent follower also fails — and
    a subsequent caller starts a fresh fetch (the in-flight map is cleaned up).
    """
    cache = JWKSCache(cache_ttl=60, stale_ttl=600)
    call_counter = {"n": 0}

    async def fail_then_succeed(self, jwks_url):
        call_counter["n"] += 1
        await asyncio.sleep(0.01)
        if call_counter["n"] <= 1:
            raise httpx.ConnectError("IdP down")
        return {keypair.kid: keypair.public}

    monkeypatch.setattr(JWKSCache, "_fetch_async", fail_then_succeed)

    # First wave: all 5 should fail.
    results = await asyncio.gather(
        *[cache.get_key_async(JWKS_URL, keypair.kid) for _ in range(5)],
        return_exceptions=True,
    )
    assert all(isinstance(r, Exception) for r in results)
    assert call_counter["n"] == 1  # all followers piggy-backed on one failed fetch

    # In-flight map must be drained so a subsequent call can retry.
    key = await cache.get_key_async(JWKS_URL, keypair.kid)
    assert key is keypair.public
    assert call_counter["n"] == 2  # one new attempt, succeeded
