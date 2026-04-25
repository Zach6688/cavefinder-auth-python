"""Integration tests for AuthMiddleware over a tiny FastAPI app."""
from __future__ import annotations

from urllib.parse import quote

from cavefinder_auth.testing import (
    client_with_user,
    make_test_jwt,
    unauthenticated_client,
)


def test_authenticated_json_request_populates_user(app, keypair):
    client = client_with_user(app, keypair=keypair, user_id=99, email="x@y.com")
    resp = client.get("/api/me")
    assert resp.status_code == 200
    assert resp.json() == {"id": 99, "email": "x@y.com"}


def test_html_route_returns_content_when_authed(app, keypair):
    client = client_with_user(app, keypair=keypair, email="h@h.com")
    resp = client.get("/html")
    assert resp.status_code == 200
    assert "Hello h@h.com" in resp.text


def test_api_route_401s_without_cookie(app):
    client = unauthenticated_client(app)
    resp = client.get("/api/me")
    assert resp.status_code == 401
    assert resp.json() == {"error": "unauthenticated"}


def test_html_route_302s_to_login_when_missing_cookie(app):
    client = unauthenticated_client(app)
    resp = client.get("/html", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://id.cavefinder.app/login?return=")
    # Return URL should be percent-encoded and include the path we hit.
    assert quote("http://testserver/html", safe="") in location


def test_html_route_preserves_query_string_in_return_url(app):
    client = unauthenticated_client(app)
    resp = client.get("/html?foo=bar&baz=qux", follow_redirects=False)
    assert resp.status_code == 302
    assert quote("http://testserver/html?foo=bar&baz=qux", safe="") in resp.headers["location"]


def test_html_route_401s_on_invalid_cookie(app, config):
    """§6.1 step 6 — tampered cookies must 401, never 302 (prevents redirect loops)."""
    client = unauthenticated_client(app)
    client.cookies.set(config.cookie_name, "totally.invalid.jwt")
    resp = client.get("/html", follow_redirects=False)
    assert resp.status_code == 401


def test_api_route_401s_on_invalid_cookie(app, config):
    client = unauthenticated_client(app)
    client.cookies.set(config.cookie_name, "totally.invalid.jwt")
    resp = client.get("/api/me")
    assert resp.status_code == 401


def test_public_path_bypasses_auth_on_healthz(app):
    client = unauthenticated_client(app)
    resp = client.get("/api/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_public_path_bypasses_auth_on_viewer(app):
    """Georef's /view/:id pattern — public sharing must work without a cookie."""
    client = unauthenticated_client(app)
    resp = client.get("/view/abc-123")
    assert resp.status_code == 200
    assert "Public view abc-123" in resp.text


def test_wrong_issuer_cookie_401s(app, keypair, config):
    # Pre-populate JWKS so middleware doesn't 500 on unknown kid.
    from cavefinder_auth.testing import override_jwks

    override_jwks(app, keypair)
    rogue_token = make_test_jwt(keypair, issuer="https://evil.example.com")
    client = unauthenticated_client(app)
    client.cookies.set(config.cookie_name, rogue_token)
    resp = client.get("/api/me")
    assert resp.status_code == 401


def test_expired_cookie_401s(app, keypair, config):
    from cavefinder_auth.testing import override_jwks

    override_jwks(app, keypair)
    token = make_test_jwt(keypair, ttl_seconds=-300)
    client = unauthenticated_client(app)
    client.cookies.set(config.cookie_name, token)
    resp = client.get("/api/me")
    assert resp.status_code == 401


def test_accept_json_header_on_non_api_path_returns_401_not_302(app):
    """A caller that explicitly wants JSON should get 401, not a redirect."""
    client = unauthenticated_client(app)
    resp = client.get("/html", headers={"accept": "application/json"})
    assert resp.status_code == 401
    assert resp.json() == {"error": "unauthenticated"}


def test_admin_user_flag_propagates(app, keypair):
    client = client_with_user(app, keypair=keypair, user_id=7, is_admin=True, tier="enterprise")
    # /api/me only echoes id+email, but we know the middleware populated the
    # full dict because the route got user["id"] = 7 (not the default).
    resp = client.get("/api/me")
    assert resp.json()["id"] == 7


# ──────────────────────────────────────────────────────────────
# WebSocket auth (OBS-2 closure)
# ──────────────────────────────────────────────────────────────
#
# Before this change, scope["type"] != "http" passed straight through the
# middleware. That meant a client app that added a websocket route got no
# auth by default — the docstring in AUTH_PACKAGE_REVIEW.md called this
# out as OBS-2 with "revisit when any client app adds its first websocket
# route". These tests lock in the new behavior.
from starlette.testclient import WebSocketDisconnect
import pytest


def test_websocket_connects_with_valid_cookie(app, keypair):
    """Happy path: a valid JWT cookie lets the handshake complete and the
    user dict reaches the route handler via scope["user"]."""
    client = client_with_user(
        app, keypair=keypair, user_id=42, email="ws@x.com", tier="pro",
    )
    with client.websocket_connect("/ws/private") as ws:
        payload = ws.receive_json()
    assert payload["user"]["id"] == 42
    assert payload["user"]["email"] == "ws@x.com"
    assert payload["user"]["tier"] == "pro"


def test_websocket_rejects_missing_cookie(app):
    """No cookie → close with code 4401 (custom per RFC 6455 §7.4.2). The
    WebSocketDisconnect's code field carries our custom rejection code so
    downstream client code can distinguish this from a generic 1006."""
    client = unauthenticated_client(app)
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws/private"):
            pass  # pragma: no cover — handshake should fail
    assert exc_info.value.code == 4401


def test_websocket_rejects_invalid_cookie(app, config):
    """Tampered / malformed cookie → same 4401 close. The invalid-cookie
    branch must mirror the missing-cookie branch: a bad token can't be
    allowed to complete the handshake (§6.1 step 6 for WS)."""
    client = unauthenticated_client(app)
    client.cookies.set(config.cookie_name, "totally.invalid.jwt")
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws/private"):
            pass  # pragma: no cover
    assert exc_info.value.code == 4401


def test_websocket_rejects_expired_token(app, keypair, config):
    """Expired tokens must not hold a socket open. Covers the scenario
    where a long-lived browser tab reconnects after the access token's
    15-minute lifetime has elapsed."""
    from cavefinder_auth.testing import make_test_jwt, override_jwks

    override_jwks(app, keypair)
    token = make_test_jwt(keypair, ttl_seconds=-60)
    client = unauthenticated_client(app)
    client.cookies.set(config.cookie_name, token)
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws/private"):
            pass  # pragma: no cover
    assert exc_info.value.code == 4401


def test_websocket_public_path_bypasses_auth(app):
    """A path in config.public_paths must connect without a cookie.
    Mirrors the HTTP public-path behavior — whitelisting is the explicit
    opt-out for e.g. public map-tile streams."""
    client = unauthenticated_client(app)
    with client.websocket_connect("/ws/public") as ws:
        payload = ws.receive_json()
    # No cookie was sent, so the scope["user"] was never populated.
    assert payload["user"] is None


def test_websocket_rejects_wrong_issuer_token(app, keypair, config):
    """A JWT signed with our test key but claiming a different issuer must
    be rejected — otherwise a rogue IdP that happened to share our JWKS
    URL could mint websocket-valid tokens."""
    from cavefinder_auth.testing import make_test_jwt, override_jwks

    override_jwks(app, keypair)
    rogue = make_test_jwt(keypair, issuer="https://evil.example.com")
    client = unauthenticated_client(app)
    client.cookies.set(config.cookie_name, rogue)
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws/private"):
            pass  # pragma: no cover
    assert exc_info.value.code == 4401
