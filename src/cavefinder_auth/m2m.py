"""Machine-to-machine bearer-token auth for internal endpoints.

DESIGN.md §7.4:
    * cavefinder → IdP: token ``CAVEID_SERVICE_TOKEN`` (Stripe forwarding, etc.)
    * IdP → georef/surveylens/cavefinder: per-target deletion-cascade tokens.

Each side stores only the **SHA-256 hash** of the shared secret in its env
(``CAVEID_TO_GEOREF_TOKEN_SHA256``, etc.), never the raw token. The raw token
lives only on the caller. This module verifies incoming bearer tokens against
that hash in constant time.

Usage on the receiving side (e.g. georef's cascade endpoint)::

    from fastapi import Depends, FastAPI
    from cavefinder_auth import require_m2m_token

    app = FastAPI()

    @app.delete("/api/v1/_internal/users/{user_id}/data")
    def cascade_delete(
        user_id: int,
        _: None = Depends(require_m2m_token(expected_hash_env="CAVEID_TO_GEOREF_TOKEN_SHA256")),
    ):
        delete_all_user_data(user_id)
        return {"ok": True}

For testing you can pass ``expected_hash`` directly instead of reading env.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Callable

from starlette.requests import Request

from .errors import M2MAuthError


def hash_token(raw_token: str) -> str:
    """SHA-256 hex digest — mirrors core.crypto.hash_token on the IdP side."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def verify_m2m_token(raw_token: str, expected_hash: str) -> bool:
    """Constant-time compare of ``sha256(raw_token)`` against the stored hash."""
    if not raw_token or not expected_hash:
        return False
    computed = hash_token(raw_token)
    return hmac.compare_digest(computed, expected_hash)


def extract_bearer_token(request: Request) -> str | None:
    """Pull the raw token out of ``Authorization: Bearer <token>`` (case-insensitive)."""
    header = request.headers.get("authorization", "")
    if not header:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def require_m2m_token(
    *,
    expected_hash_env: str | None = None,
    expected_hash: str | None = None,
) -> Callable[[Request], None]:
    """FastAPI dependency factory — returns a callable that 401s on bad/missing tokens.

    Exactly one of ``expected_hash_env`` (name of env var to read at dependency
    resolve time) or ``expected_hash`` (literal hex string, useful for tests)
    must be supplied. Reading from env **per-request** means a rotation can take
    effect without restarting the process — set the new env var, the next request
    picks it up. In production we still restart on rotation so the old token is
    instantly invalid, but this gives us a grace window during deploys.
    """
    if (expected_hash_env is None) == (expected_hash is None):
        raise ValueError("supply exactly one of expected_hash_env or expected_hash")

    def _dep(request: Request) -> None:
        resolved = expected_hash if expected_hash is not None else os.environ.get(expected_hash_env or "")
        if not resolved:
            raise _m2m_401("service token not configured")
        raw = extract_bearer_token(request)
        if not raw:
            raise _m2m_401("missing bearer token")
        if not verify_m2m_token(raw, resolved):
            raise _m2m_401("invalid bearer token")
        return None

    return _dep


def _m2m_401(detail: str) -> Exception:
    """Build a 401 exception — HTTPException if FastAPI is installed, else M2MAuthError.

    Returning (not raising) lets callers decide exception framing; ``raise _m2m_401(...)``
    is the usual pattern.
    """
    try:
        from fastapi import HTTPException
    except ImportError:  # pragma: no cover — fastapi is declared as a dep of the `testing` extra
        return M2MAuthError(detail)
    return HTTPException(status_code=401, detail=detail)
