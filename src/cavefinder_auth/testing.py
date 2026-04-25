"""Fixtures for client-app tests.

DESIGN.md §6.1 mandates a ``cavefinder_auth.testing`` module so the three client
apps can write auth-aware tests without rebuilding JWKS plumbing. Everything here
is test-only — imports FastAPI's TestClient lazily so production installs can skip
that dependency.

Typical usage in a client app's conftest.py::

    from cavefinder_auth.testing import (
        generate_test_keypair,
        make_test_jwt,
        override_jwks,
        client_with_user,
    )

    @pytest.fixture
    def keypair():
        return generate_test_keypair()

    @pytest.fixture
    def client(app, keypair):
        override_jwks(app, keypair)
        return client_with_user(app, keypair=keypair, user_id=1, email="t@x.com", tier="pro")
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .config import DEFAULT_COOKIE_NAME
from .jwks import JWKSCache
from .middleware import AuthMiddleware


DEFAULT_TEST_KID = "test-key-1"
DEFAULT_TEST_ISSUER = "https://id.cavefinder.app"


@dataclass(frozen=True)
class TestKeypair:
    """Bundle of (private, public, kid) for signing + verifying test JWTs."""

    private: RSAPrivateKey
    public: RSAPublicKey
    kid: str = DEFAULT_TEST_KID


def generate_test_keypair(kid: str = DEFAULT_TEST_KID, *, bits: int = 2048) -> TestKeypair:
    """Fresh RSA keypair for a single test run. 2048 bits is plenty — we're not
    protecting real secrets, and larger keys make test startup noticeably slower."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return TestKeypair(private=private, public=private.public_key(), kid=kid)


def make_test_jwt(
    keypair: TestKeypair,
    *,
    user_id: int = 1,
    email: str = "test@example.com",
    display_name: str = "Test User",
    tier: str = "free",
    email_verified: bool = True,
    is_admin: bool = False,
    impersonator_id: int | None = None,
    issuer: str = DEFAULT_TEST_ISSUER,
    ttl_seconds: int = 15 * 60,
    now: float | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Sign a JWT that matches what the IdP produces (same claim shape)."""
    now_ts = int(now if now is not None else time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": str(user_id),
        "email": email,
        "display_name": display_name,
        "tier": tier,
        "email_verified": bool(email_verified),
        "is_admin": bool(is_admin),
        "iat": now_ts,
        "exp": now_ts + ttl_seconds,
    }
    if impersonator_id is not None:
        claims["imp"] = int(impersonator_id)
    if extra_claims:
        claims.update(extra_claims)

    private_pem = keypair.private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(
        claims,
        private_pem,
        algorithm="RS256",
        headers={"kid": keypair.kid},
    )


def override_jwks(app: Any, keypair: TestKeypair) -> None:
    """Point every AuthMiddleware on ``app`` at the test keypair.

    Walks the Starlette middleware stack (``app.user_middleware`` on FastAPI),
    finds each ``AuthMiddleware`` instance, and pre-populates its JWKS cache
    with the test public key. Also installs the override on the cache so even
    if the middleware is later re-instantiated it picks up the fixture key.
    """
    caches = _collect_auth_middleware_caches(app)
    if not caches:
        raise RuntimeError(
            "No AuthMiddleware found on app — did you call app.add_middleware(AuthMiddleware, ...)?"
        )
    for cache, jwks_url in caches:
        cache.set_override(jwks_url, {keypair.kid: keypair.public})


def _collect_auth_middleware_caches(app: Any) -> list[tuple[JWKSCache, str]]:
    """Find every ``AuthMiddleware`` cache + its configured JWKS URL.

    FastAPI stores middleware definitions on ``app.user_middleware`` as a list of
    ``Middleware`` objects with ``cls`` / ``kwargs``. The actual middleware
    **instances** aren't created until ``app.build_middleware_stack()`` runs
    (triggered on first request). To override cleanly we force that build now,
    then walk the live ASGI chain.
    """
    # Force middleware instantiation. Works for both FastAPI (has ``middleware_stack``
    # attr) and raw Starlette.
    if hasattr(app, "build_middleware_stack"):
        app.middleware_stack = app.build_middleware_stack()

    found: list[tuple[JWKSCache, str]] = []
    seen_ids: set[int] = set()

    def _walk(node: Any) -> None:
        if node is None or id(node) in seen_ids:
            return
        seen_ids.add(id(node))
        if isinstance(node, AuthMiddleware):
            found.append((node.jwks_cache, node.config.jwks_url))
        # Starlette wraps middleware as ``.app`` attributes. ExceptionMiddleware,
        # ServerErrorMiddleware, CORSMiddleware etc. all follow the same pattern.
        inner = getattr(node, "app", None)
        if inner is not None and inner is not node:
            _walk(inner)

    _walk(getattr(app, "middleware_stack", None) or app)
    return found


def client_with_user(
    app: Any,
    *,
    keypair: TestKeypair,
    user_id: int = 1,
    email: str = "test@example.com",
    display_name: str = "Test User",
    tier: str = "free",
    email_verified: bool = True,
    is_admin: bool = False,
    impersonator_id: int | None = None,
    issuer: str = DEFAULT_TEST_ISSUER,
    cookie_name: str = DEFAULT_COOKIE_NAME,
    base_url: str = "http://testserver",
) -> Any:
    """Return a ``TestClient`` pre-loaded with the __Secure-cf_at cookie.

    All requests made with this client will be authenticated as the given user.
    Automatically calls :func:`override_jwks` so verification works with the
    fixture keypair. Lazy-imports ``fastapi.testclient`` so production deps
    stay lean.
    """
    override_jwks(app, keypair)

    token = make_test_jwt(
        keypair,
        user_id=user_id,
        email=email,
        display_name=display_name,
        tier=tier,
        email_verified=email_verified,
        is_admin=is_admin,
        impersonator_id=impersonator_id,
        issuer=issuer,
    )

    try:
        from fastapi.testclient import TestClient
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "client_with_user requires FastAPI — install cavefinder-auth[testing]"
        ) from exc

    client = TestClient(app, base_url=base_url)
    # TestClient's cookies attribute accepts __Secure- prefixed names but won't
    # actually send them over non-HTTPS unless we set the cookie via the jar
    # without the Secure flag. Since TestClient uses an in-memory transport
    # (not real HTTP), Secure-flag enforcement is moot — just stash the value.
    client.cookies.set(cookie_name, token)
    return client


def unauthenticated_client(app: Any, *, base_url: str = "http://testserver") -> Any:
    """A TestClient with no auth cookie — useful for testing the 401 / 302 flows."""
    try:
        from fastapi.testclient import TestClient
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "unauthenticated_client requires FastAPI — install cavefinder-auth[testing]"
        ) from exc
    return TestClient(app, base_url=base_url)
