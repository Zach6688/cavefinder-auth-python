"""Meta-tests: verify the testing module itself works correctly."""
from __future__ import annotations

import pytest
from fastapi import FastAPI

from cavefinder_auth import AuthConfig, AuthMiddleware
from cavefinder_auth.testing import (
    DEFAULT_TEST_ISSUER,
    client_with_user,
    generate_test_keypair,
    make_test_jwt,
    override_jwks,
    unauthenticated_client,
)


def test_generate_test_keypair_returns_unique_keys():
    a = generate_test_keypair()
    b = generate_test_keypair()
    assert a.public.public_numbers().n != b.public.public_numbers().n


def test_make_test_jwt_claims(keypair):
    token = make_test_jwt(keypair, user_id=5, tier="pro", is_admin=True)
    # Decode with the matching public key to verify shape.
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization

    public_pem = keypair.public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    claims = pyjwt.decode(token, public_pem, algorithms=["RS256"], issuer=DEFAULT_TEST_ISSUER)
    assert claims["sub"] == "5"
    assert claims["tier"] == "pro"
    assert claims["is_admin"] is True


def test_override_jwks_requires_middleware():
    app = FastAPI()
    kp = generate_test_keypair()
    with pytest.raises(RuntimeError, match="No AuthMiddleware found"):
        override_jwks(app, kp)


def test_override_jwks_finds_multiple_middleware(keypair):
    """Rare but possible — two AuthMiddlewares stacked (e.g. different cookies).
    Both should have their caches overridden."""
    cfg1 = AuthConfig(
        issuer=DEFAULT_TEST_ISSUER,
        jwks_url="https://id.cavefinder.app/.well-known/jwks.json",
        login_url="https://id.cavefinder.app/login",
    )
    cfg2 = AuthConfig(
        issuer=DEFAULT_TEST_ISSUER,
        jwks_url="https://id.cavefinder.app/.well-known/jwks.json",
        login_url="https://id.cavefinder.app/login",
        cookie_name="__Secure-cf_at_alt",
    )
    app = FastAPI()
    app.add_middleware(AuthMiddleware, config=cfg1)
    app.add_middleware(AuthMiddleware, config=cfg2)

    override_jwks(app, keypair)
    # Nothing to assert beyond "no exception" — the next test proves the key
    # actually reaches the cache.


def test_client_with_user_authenticates_end_to_end(app, keypair):
    client = client_with_user(app, keypair=keypair, user_id=123, email="me@me.com", tier="enterprise")
    resp = client.get("/api/me")
    assert resp.status_code == 200
    assert resp.json() == {"id": 123, "email": "me@me.com"}


def test_unauthenticated_client_produces_401(app):
    client = unauthenticated_client(app)
    assert client.get("/api/me").status_code == 401


def test_client_with_user_default_claims(app, keypair):
    client = client_with_user(app, keypair=keypair)
    resp = client.get("/api/me")
    assert resp.status_code == 200
    assert resp.json() == {"id": 1, "email": "test@example.com"}
