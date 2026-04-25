"""Paste into SurveyLens's tests/conftest.py.

Provides a ready-to-use authenticated client fixture that every test can use to
hit protected routes without re-plumbing JWKS per test.

Usage in a test::

    def test_analyze_endpoint(authed_client):
        resp = authed_client.post("/api/v1/analyze", json={"input": "…"})
        assert resp.status_code == 200
"""
from __future__ import annotations

import os

import pytest

from cavefinder_auth import hash_token
from cavefinder_auth.testing import (
    client_with_user,
    generate_test_keypair,
    unauthenticated_client,
)


@pytest.fixture(autouse=True)
def _stub_m2m_token(monkeypatch):
    """Every test gets the cascade M2M token pre-configured so cascade tests work
    without leaking real secrets. Value is deterministic per-test-run; tests that
    want to verify rejection override with a different value."""
    monkeypatch.setenv(
        "CAVEID_TO_SURVEYLENS_TOKEN_SHA256",
        hash_token("test-cascade-token"),
    )
    yield


@pytest.fixture
def keypair():
    return generate_test_keypair()


@pytest.fixture
def app():
    # Import inside the fixture so main.py sees the patched env vars above.
    from main import app as fastapi_app
    return fastapi_app


@pytest.fixture
def authed_client(app, keypair):
    """TestClient pre-loaded with a valid __Secure-cf_at cookie for user_id=1."""
    return client_with_user(
        app,
        keypair=keypair,
        user_id=1,
        email="pytest@example.com",
        tier="pro",
    )


@pytest.fixture
def anon_client(app):
    """TestClient with no auth cookie — for testing 401 flows."""
    return unauthenticated_client(app)
