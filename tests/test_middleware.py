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
