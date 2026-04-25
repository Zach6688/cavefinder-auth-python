"""Shared fixtures for cavefinder-auth package tests.

These tests exercise the package as a standalone FastAPI consumer would — we
build a tiny throw-away FastAPI app per test and mount the middleware on it.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse

from cavefinder_auth import AuthConfig, AuthMiddleware
from cavefinder_auth.testing import DEFAULT_TEST_ISSUER, generate_test_keypair


@pytest.fixture
def keypair():
    return generate_test_keypair()


@pytest.fixture
def config():
    return AuthConfig(
        issuer=DEFAULT_TEST_ISSUER,
        jwks_url="https://id.cavefinder.app/.well-known/jwks.json",
        login_url="https://id.cavefinder.app/login",
        # /ws/public exercises the public-path bypass for websockets.
        public_paths=("/api/healthz", "/static", "/view", "/ws/public"),
    )


@pytest.fixture
def app(config):
    """Minimal FastAPI app with the auth middleware + a handful of routes.

    Routes cover the matrix the middleware needs to distinguish:
      * /api/* → JSON response semantics
      * /html → HTML route (302 on missing cookie)
      * /api/healthz → public path
      * /view/abc123 → public path (viewer pattern from georef)
    """
    app = FastAPI()
    app.add_middleware(AuthMiddleware, config=config)

    @app.get("/api/me")
    def me(request: Request):
        user = request.state.user
        return {"id": user["id"], "email": user["email"]}

    @app.get("/api/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/html", response_class=HTMLResponse)
    def html_page(request: Request):
        user = request.state.user
        return f"<h1>Hello {user['email']}</h1>"

    @app.get("/view/{project_id}", response_class=HTMLResponse)
    def viewer(project_id: str):
        return f"<h1>Public view {project_id}</h1>"

    # WebSocket routes for OBS-2 coverage. /ws/private is auth-required;
    # /ws/public is whitelisted via public_paths. Both just echo the user
    # dict (or "anonymous") so tests can assert on what reached the handler.
    @app.websocket("/ws/private")
    async def ws_private(websocket: WebSocket):
        user = websocket.scope.get("user")
        await websocket.accept()
        await websocket.send_json({"user": user})
        await websocket.close()

    @app.websocket("/ws/public")
    async def ws_public(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_json({"user": websocket.scope.get("user")})
        await websocket.close()

    return app
