"""Smoke tests for the Flask cavefinder-auth adapter (flask_auth.py).

These verify the three pieces that are easy to get wrong when re-implementing
middleware outside of Starlette:

  1. @login_required returns 401 JSON for /api/ paths even when the Accept header
     says text/html (API routes must never redirect).
  2. @login_required returns 302 to the IdP login URL for HTML routes.
  3. @require_m2m_token_flask rejects missing / wrong bearer tokens and accepts
     the right one, reading the hash from env per-request (rotation-friendly).

The cookie-verified-user path is covered via a monkeypatched decoder so we
don't have to spin up a real JWKS server here — the decode itself is covered
by the cavefinder_auth package's own test suite.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
BACKEND_DIR = HERE.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

flask = pytest.importorskip("flask")

import flask_auth  # noqa: E402  (path-hacked import)
from flask import Flask, g, jsonify  # noqa: E402


@pytest.fixture
def app(monkeypatch):
    # Pin the IdP config so the redirect URL is deterministic.
    monkeypatch.setenv("CAVEID_ISSUER", "https://id.test.local")
    monkeypatch.setenv("CAVEID_LOGIN_URL", "https://id.test.local/login")

    app = Flask(__name__)
    app.config["TESTING"] = True
    flask_auth.init_auth(app)

    @app.route("/api/me")
    @flask_auth.login_required
    def api_me():
        return jsonify(flask_auth.current_user())

    @app.route("/account")
    @flask_auth.login_required
    def account_page():
        return "<html>account</html>"

    @app.route("/api/v1/_internal/users/<int:user_id>/data", methods=["DELETE"])
    @flask_auth.require_m2m_token_flask("CAVEID_TO_CAVEFINDER_TOKEN_SHA256")
    def cascade_delete(user_id):
        return jsonify({"deleted": user_id})

    return app


# ──────────────────────────────────────────────────────────────
# @login_required behavior
# ──────────────────────────────────────────────────────────────

def test_api_route_without_cookie_returns_401_json(app):
    resp = app.test_client().get("/api/me")
    assert resp.status_code == 401
    assert resp.get_json() == {"error": "unauthenticated"}


def test_html_route_without_cookie_redirects_to_idp(app):
    resp = app.test_client().get("/account")
    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("https://id.test.local/login?return=")
    # The return URL must be percent-encoded.
    assert "%2Faccount" in resp.headers["Location"]


def test_login_required_passes_through_when_user_set(app, monkeypatch):
    """Simulate a valid cookie by short-circuiting the decoder."""
    def fake_decode(token, *, config, jwks_cache):
        assert token == "stub-jwt"
        return {"id": 42, "email": "z@example.com", "display_name": "Z",
                "tier": "pro", "email_verified": True, "is_admin": False,
                "impersonator_id": None}

    monkeypatch.setattr(flask_auth, "decode_access_token", fake_decode)
    client = app.test_client()
    client.set_cookie("__Secure-cf_at", "stub-jwt", domain="localhost")
    resp = client.get("/api/me")
    assert resp.status_code == 200
    assert resp.get_json()["id"] == 42


def test_invalid_cookie_falls_through_to_anonymous(app, monkeypatch):
    """Bad JWT must not 500 — g.user stays None and @login_required fires normally."""
    from cavefinder_auth import InvalidTokenError

    def raising_decode(token, *, config, jwks_cache):
        raise InvalidTokenError("token expired")

    monkeypatch.setattr(flask_auth, "decode_access_token", raising_decode)
    client = app.test_client()
    client.set_cookie("__Secure-cf_at", "garbage", domain="localhost")
    resp = client.get("/api/me")
    assert resp.status_code == 401


# ──────────────────────────────────────────────────────────────
# @require_m2m_token_flask behavior
# ──────────────────────────────────────────────────────────────

def test_cascade_rejects_missing_env_var(app, monkeypatch):
    monkeypatch.delenv("CAVEID_TO_CAVEFINDER_TOKEN_SHA256", raising=False)
    resp = app.test_client().delete(
        "/api/v1/_internal/users/1/data",
        headers={"Authorization": "Bearer anything"},
    )
    assert resp.status_code == 401


def test_cascade_rejects_missing_bearer(app, monkeypatch):
    import hashlib
    raw = "rotate-me"
    monkeypatch.setenv(
        "CAVEID_TO_CAVEFINDER_TOKEN_SHA256",
        hashlib.sha256(raw.encode()).hexdigest(),
    )
    resp = app.test_client().delete("/api/v1/_internal/users/1/data")
    assert resp.status_code == 401


def test_cascade_rejects_wrong_bearer(app, monkeypatch):
    import hashlib
    raw = "real-token"
    monkeypatch.setenv(
        "CAVEID_TO_CAVEFINDER_TOKEN_SHA256",
        hashlib.sha256(raw.encode()).hexdigest(),
    )
    resp = app.test_client().delete(
        "/api/v1/_internal/users/1/data",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


def test_cascade_accepts_correct_bearer(app, monkeypatch):
    import hashlib
    raw = "correct-horse-battery-staple"
    monkeypatch.setenv(
        "CAVEID_TO_CAVEFINDER_TOKEN_SHA256",
        hashlib.sha256(raw.encode()).hexdigest(),
    )
    resp = app.test_client().delete(
        "/api/v1/_internal/users/42/data",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"deleted": 42}


def test_cascade_bearer_is_case_insensitive_scheme(app, monkeypatch):
    """Authorization: BEARER <token> (RFC 7235 says scheme is case-insensitive)."""
    import hashlib
    raw = "case-test"
    monkeypatch.setenv(
        "CAVEID_TO_CAVEFINDER_TOKEN_SHA256",
        hashlib.sha256(raw.encode()).hexdigest(),
    )
    resp = app.test_client().delete(
        "/api/v1/_internal/users/42/data",
        headers={"Authorization": f"BEARER {raw}"},
    )
    assert resp.status_code == 200
