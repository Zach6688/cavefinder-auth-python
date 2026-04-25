"""Machine-to-machine bearer-token tests."""
from __future__ import annotations

import os

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from cavefinder_auth import hash_token, require_m2m_token, verify_m2m_token
from cavefinder_auth.m2m import extract_bearer_token


def test_hash_token_is_sha256_hex():
    assert hash_token("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_verify_m2m_token_happy_path():
    secret = "totally-random-secret"
    assert verify_m2m_token(secret, hash_token(secret)) is True


def test_verify_m2m_token_rejects_wrong_secret():
    assert verify_m2m_token("wrong", hash_token("right")) is False


def test_verify_m2m_token_rejects_empty_inputs():
    assert verify_m2m_token("", hash_token("x")) is False
    assert verify_m2m_token("x", "") is False


def test_extract_bearer_token_handles_case():
    from starlette.requests import Request

    req = Request({"type": "http", "headers": [(b"authorization", b"BEARER abc123")]})
    assert extract_bearer_token(req) == "abc123"


def test_extract_bearer_token_rejects_non_bearer_scheme():
    from starlette.requests import Request

    req = Request({"type": "http", "headers": [(b"authorization", b"Basic dXNlcjpwdw==")]})
    assert extract_bearer_token(req) is None


def test_extract_bearer_token_missing_header():
    from starlette.requests import Request

    req = Request({"type": "http", "headers": []})
    assert extract_bearer_token(req) is None


# ──────────────────────────────────────────────────────────────
# FastAPI dependency integration
# ──────────────────────────────────────────────────────────────
@pytest.fixture
def protected_app():
    app = FastAPI()

    @app.delete("/api/v1/_internal/users/{user_id}/data")
    def cascade(
        user_id: int,
        _: None = Depends(require_m2m_token(expected_hash=hash_token("shared-secret"))),
    ):
        return {"ok": True, "user_id": user_id}

    return app


def test_cascade_endpoint_accepts_valid_token(protected_app):
    client = TestClient(protected_app)
    resp = client.delete(
        "/api/v1/_internal/users/42/data",
        headers={"authorization": "Bearer shared-secret"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "user_id": 42}


def test_cascade_endpoint_rejects_missing_header(protected_app):
    client = TestClient(protected_app)
    resp = client.delete("/api/v1/_internal/users/42/data")
    assert resp.status_code == 401


def test_cascade_endpoint_rejects_wrong_token(protected_app):
    client = TestClient(protected_app)
    resp = client.delete(
        "/api/v1/_internal/users/42/data",
        headers={"authorization": "Bearer nope"},
    )
    assert resp.status_code == 401


def test_cascade_endpoint_rejects_non_bearer_scheme(protected_app):
    client = TestClient(protected_app)
    resp = client.delete(
        "/api/v1/_internal/users/42/data",
        headers={"authorization": "Basic dXNlcjpwdw=="},
    )
    assert resp.status_code == 401


def test_require_m2m_token_reads_env_at_request_time(monkeypatch):
    app = FastAPI()

    @app.get("/ping")
    def ping(_: None = Depends(require_m2m_token(expected_hash_env="MY_SERVICE_TOKEN_SHA256"))):
        return {"ok": True}

    client = TestClient(app)

    # Env not set — 401.
    monkeypatch.delenv("MY_SERVICE_TOKEN_SHA256", raising=False)
    resp = client.get("/ping", headers={"authorization": "Bearer anything"})
    assert resp.status_code == 401

    # Set it — same token now works.
    monkeypatch.setenv("MY_SERVICE_TOKEN_SHA256", hash_token("rotated-secret"))
    resp = client.get("/ping", headers={"authorization": "Bearer rotated-secret"})
    assert resp.status_code == 200


def test_require_m2m_token_rejects_both_args_missing():
    with pytest.raises(ValueError):
        require_m2m_token()


def test_require_m2m_token_rejects_both_args_set():
    with pytest.raises(ValueError):
        require_m2m_token(expected_hash="a", expected_hash_env="B")
