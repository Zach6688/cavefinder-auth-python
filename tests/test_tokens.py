"""Direct unit tests for the decode_access_token helper."""
from __future__ import annotations

import time

import pytest

from cavefinder_auth import (
    AuthConfig,
    InvalidTokenError,
    JWKSCache,
    decode_access_token,
)
from cavefinder_auth.testing import (
    DEFAULT_TEST_ISSUER,
    generate_test_keypair,
    make_test_jwt,
)


@pytest.fixture
def cache_with_key(keypair):
    cache = JWKSCache()
    cache.set_override(
        "https://id.cavefinder.app/.well-known/jwks.json",
        {keypair.kid: keypair.public},
    )
    return cache


@pytest.fixture
def cfg():
    return AuthConfig(
        issuer=DEFAULT_TEST_ISSUER,
        jwks_url="https://id.cavefinder.app/.well-known/jwks.json",
        login_url="https://id.cavefinder.app/login",
    )


def test_decode_returns_user_dict(keypair, cache_with_key, cfg):
    token = make_test_jwt(keypair, user_id=42, email="a@b.com", tier="pro", is_admin=True)
    user = decode_access_token(token, config=cfg, jwks_cache=cache_with_key)
    assert user == {
        "id": 42,
        "email": "a@b.com",
        "display_name": "Test User",
        "tier": "pro",
        "email_verified": True,
        "is_admin": True,
        "impersonator_id": None,
    }


def test_decode_surfaces_impersonator_id(keypair, cache_with_key, cfg):
    token = make_test_jwt(keypair, user_id=10, impersonator_id=1)
    user = decode_access_token(token, config=cfg, jwks_cache=cache_with_key)
    assert user["impersonator_id"] == 1


def test_decode_rejects_empty_string(cache_with_key, cfg):
    with pytest.raises(InvalidTokenError):
        decode_access_token("", config=cfg, jwks_cache=cache_with_key)


def test_decode_rejects_malformed(cache_with_key, cfg):
    with pytest.raises(InvalidTokenError):
        decode_access_token("not.a.jwt", config=cfg, jwks_cache=cache_with_key)


def test_decode_rejects_wrong_issuer(keypair, cache_with_key, cfg):
    token = make_test_jwt(keypair, issuer="https://evil.example.com")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, config=cfg, jwks_cache=cache_with_key)


def test_decode_rejects_expired(keypair, cache_with_key, cfg):
    # ttl = -60 makes exp in the past; leeway is 30 so even with slack it's invalid.
    token = make_test_jwt(keypair, ttl_seconds=-120, now=time.time())
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, config=cfg, jwks_cache=cache_with_key)


def test_decode_honors_leeway(keypair, cache_with_key, cfg):
    # Expired by 10 seconds — inside the 30 s default leeway, should still pass.
    token = make_test_jwt(keypair, ttl_seconds=-10)
    user = decode_access_token(token, config=cfg, jwks_cache=cache_with_key)
    assert user["id"] == 1


def test_decode_rejects_wrong_signature(cache_with_key, cfg):
    # Sign with a DIFFERENT keypair than the cache knows about.
    rogue = generate_test_keypair(kid="test-key-1")  # same kid, different key
    bad_token = make_test_jwt(rogue)
    with pytest.raises(InvalidTokenError):
        decode_access_token(bad_token, config=cfg, jwks_cache=cache_with_key)


def test_decode_rejects_unknown_kid(keypair, cfg):
    cache = JWKSCache()
    cache.set_override(cfg.jwks_url, {"different-kid": keypair.public})
    token = make_test_jwt(keypair)  # token has kid=test-key-1
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, config=cfg, jwks_cache=cache)


def test_decode_rejects_hs256_tokens(keypair, cache_with_key, cfg):
    """Critical §5.5 guardrail — the decoder must refuse HS256 tokens regardless
    of the secret used. Passing ``algorithms=['RS256']`` to PyJWT is what enforces
    this; the test pins that behavior so a future refactor can't accidentally
    allow the alg-confusion family of attacks.

    Modern PyJWT also refuses to ``encode`` with a PEM public key as the HMAC
    secret (so the classic "sign with the public key" attack is a double-fail),
    but we don't rely on that — we sign with a plain string secret and still
    expect rejection.
    """
    import jwt as pyjwt

    attack = pyjwt.encode(
        {"iss": DEFAULT_TEST_ISSUER, "sub": "1"},
        "any-shared-secret",
        algorithm="HS256",
        headers={"kid": keypair.kid},
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(attack, config=cfg, jwks_cache=cache_with_key)


def test_decode_rejects_missing_kid(keypair, cache_with_key, cfg):
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization

    private_pem = keypair.private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = pyjwt.encode(
        {"iss": DEFAULT_TEST_ISSUER, "sub": "1", "exp": int(time.time()) + 60},
        private_pem,
        algorithm="RS256",
        # no kid header
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, config=cfg, jwks_cache=cache_with_key)
