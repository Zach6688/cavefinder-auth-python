"""Verification tests for the cascade stub. Paste into tests/test_cascade.py.

These tests prove the stub conforms to the IdP's cascade orchestrator contract:
  * 204 on valid bearer
  * 401 on missing or wrong bearer
  * 401 if the env var is unset (fail-closed)
"""
from __future__ import annotations

from fastapi.testclient import TestClient

# The conftest_patch.py fixture seeds CAVEID_TO_SURVEYLENS_TOKEN_SHA256 with
# the hash of "test-cascade-token" so the following tests can use it verbatim.
VALID_RAW = "test-cascade-token"


def test_cascade_returns_204_with_valid_bearer(app):
    client = TestClient(app)
    resp = client.delete(
        "/api/v1/_internal/users/42/data",
        headers={"authorization": f"Bearer {VALID_RAW}"},
    )
    assert resp.status_code == 204
    assert resp.content == b""


def test_cascade_rejects_missing_bearer(app):
    client = TestClient(app)
    resp = client.delete("/api/v1/_internal/users/42/data")
    assert resp.status_code == 401


def test_cascade_rejects_wrong_bearer(app):
    client = TestClient(app)
    resp = client.delete(
        "/api/v1/_internal/users/42/data",
        headers={"authorization": "Bearer nope"},
    )
    assert resp.status_code == 401


def test_cascade_rejects_when_env_unset(app, monkeypatch):
    monkeypatch.delenv("CAVEID_TO_SURVEYLENS_TOKEN_SHA256", raising=False)
    client = TestClient(app)
    resp = client.delete(
        "/api/v1/_internal/users/42/data",
        headers={"authorization": f"Bearer {VALID_RAW}"},
    )
    assert resp.status_code == 401


def test_cascade_bypasses_cookie_auth(app):
    """The /_internal prefix is in public_paths, so cookie auth doesn't fire.
    Proof: call succeeds with a bearer and NO __Secure-cf_at cookie."""
    client = TestClient(app)
    assert "__Secure-cf_at" not in client.cookies
    resp = client.delete(
        "/api/v1/_internal/users/1/data",
        headers={"authorization": f"Bearer {VALID_RAW}"},
    )
    assert resp.status_code == 204
