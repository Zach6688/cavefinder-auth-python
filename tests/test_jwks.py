"""JWKS cache + parser tests. HTTP is stubbed — no real network."""
from __future__ import annotations

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
# Negative cache for unknown kids (OBS-1 mitigation)
# ──────────────────────────────────────────────────────────────
def test_negative_cache_suppresses_repeat_unknown_kid_fetches(
    cache_with_transport, transport, keypair,
):
    """The core of OBS-1: an attacker blasting unknown kids must NOT be
    able to translate each attempt into a JWKS HTTP fetch. After the
    first unknown-kid lookup forces a refresh and still comes up empty,
    subsequent lookups with the same kid are rejected from the negative
    cache without touching the network."""
    # Populate the cache with a known key so `need_fetch` is False on
    # the unknown-kid path (which is exactly the amplification shape —
    # a warm cache + a probe with a bad kid).
    transport.payload = _jwks_for(keypair)
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    assert transport.calls == 1

    # First unknown-kid probe: forces one refresh (the existing
    # refresh-on-unknown-kid behavior), which still doesn't find it.
    with pytest.raises(JWKSFetchError):
        cache_with_transport.get_key(JWKS_URL, "attacker-kid-1")
    calls_after_first_probe = transport.calls
    assert calls_after_first_probe == 2  # 1 initial + 1 refresh-on-unknown

    # Subsequent probes for the SAME kid inside the unknown_kid_ttl
    # window must not trigger further fetches. This is the fix: without
    # the negative cache, each of the five probes below would be
    # another round-trip.
    for _ in range(5):
        with pytest.raises(JWKSFetchError):
            cache_with_transport.get_key(JWKS_URL, "attacker-kid-1")
    assert transport.calls == calls_after_first_probe, (
        "negative cache should suppress repeat fetches for the same kid"
    )


def test_negative_cache_does_not_suppress_different_kids(
    cache_with_transport, transport, keypair,
):
    """Scoping test: the negative cache is per-kid. A caught kid must not
    block a different kid from getting its legitimate refresh-on-unknown
    attempt — otherwise a single attacker probe would lock the cache
    against a genuine concurrent rotation."""
    transport.payload = _jwks_for(keypair)
    cache_with_transport.get_key(JWKS_URL, keypair.kid)
    baseline = transport.calls

    with pytest.raises(JWKSFetchError):
        cache_with_transport.get_key(JWKS_URL, "kid-A")
    after_A = transport.calls
    assert after_A == baseline + 1  # one refresh for A

    with pytest.raises(JWKSFetchError):
        cache_with_transport.get_key(JWKS_URL, "kid-B")
    after_B = transport.calls
    assert after_B == after_A + 1, (
        "a fresh unknown kid should still get its refresh attempt — "
        "negative cache is per-kid, not global"
    )


def test_negative_cache_expires_after_ttl(
    cache_with_transport, transport, keypair,
):
    """After the TTL elapses a previously-negative kid gets another
    refresh attempt — important so a legitimate rotation isn't
    permanently blocked by a one-off early probe."""
    transport.payload = _jwks_for(keypair)
    cache_with_transport.get_key(JWKS_URL, keypair.kid)  # warm
    baseline = transport.calls

    with pytest.raises(JWKSFetchError):
        cache_with_transport.get_key(JWKS_URL, "rotating-kid")
    after_first = transport.calls
    assert after_first == baseline + 1

    # Rewind the negative-cache timestamp past unknown_kid_ttl.
    cache_with_transport._unknown_kids[JWKS_URL]["rotating-kid"] = (
        time.time() - (cache_with_transport.unknown_kid_ttl + 1)
    )

    # Now the IdP has rotated and actually has the kid.
    import base64
    from cavefinder_auth.testing import generate_test_keypair

    rotated = generate_test_keypair(kid="rotating-kid")
    # Replace payload with a JWKS that contains both keypairs.
    payload = _jwks_for(keypair)
    nums = rotated.public.public_numbers()

    def _enc(v: int) -> str:
        raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    payload["keys"].append(
        {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "rotating-kid",
         "n": _enc(nums.n), "e": _enc(nums.e)}
    )
    transport.payload = payload

    # Force the cache TTL to also elapse so we don't serve the old entry
    # (the negative cache sits in front of `need_fetch`; once the TTL
    # expires the refresh path runs and populates the key).
    cache_with_transport._entries[JWKS_URL].fetched_at = (
        time.time() - (cache_with_transport.cache_ttl + 1)
    )
    key = cache_with_transport.get_key(JWKS_URL, "rotating-kid")
    assert key.public_numbers().n == rotated.public.public_numbers().n
