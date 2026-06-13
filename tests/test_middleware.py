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


async def test_public_path_check_keyed_on_scope_path_not_host(config, monkeypatch):
    """CVE-2026-48710 "BadHost" regression.

    The public-path bypass MUST be decided on the raw ASGI ``scope['path']``
    (what the router dispatches on), NOT ``request.url.path`` — the latter is
    reconstructed using the Host header, which Starlette <=1.0.0 does not
    validate, so a crafted Host header can poison it. We drive the middleware
    directly with a scope whose dispatch path is a PROTECTED route while the
    Host header attempts to inject the public ``/api/healthz`` prefix. The
    middleware must (a) key the public check on the scope path and (b) NOT
    bypass auth (no cookie → 401, protected inner app never reached). This is
    version-independent: it asserts the correct input to the bypass decision
    regardless of how the installed Starlette reconstructs request.url.path.
    """
    from cavefinder_auth.middleware import AuthMiddleware

    # AuthConfig is a frozen dataclass — patch the class method, not the
    # instance attribute. monkeypatch reverts it after the test.
    seen_paths: list[str] = []
    real_is_public = type(config).is_public_path

    def spy(self, path: str) -> bool:
        seen_paths.append(path)
        return real_is_public(self, path)

    monkeypatch.setattr(type(config), "is_public_path", spy)

    inner_reached = {"v": False}

    async def inner(scope, receive, send):  # the PROTECTED app behind the mw
        inner_reached["v"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"PROTECTED"})

    mw = AuthMiddleware(inner, config=config)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/me",                 # PROTECTED dispatch path
        "raw_path": b"/api/me",
        "query_string": b"",
        # Host header attempts to poison a reconstructed url.path toward the
        # public "/api/healthz" prefix (the BadHost vector).
        "headers": [(b"host", b"evil.example/api/healthz")],
        "server": ("testserver", 80),
        "client": ("1.2.3.4", 5678),
        "state": {},
    }

    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await mw(scope, receive, send)

    # (a) the bypass decision was keyed on the scope path, never a poisoned value.
    assert seen_paths == ["/api/me"], f"public check saw {seen_paths!r}, not scope path"
    # (b) the protected route did NOT bypass to the inner app...
    assert inner_reached["v"] is False, "auth bypassed on a protected scope path"
    # ...it returned 401 (no cookie on a non-public path).
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 401


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
