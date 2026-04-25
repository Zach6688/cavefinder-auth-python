"""Cascade-delete stub for SurveyLens.

Per cave-id/DESIGN.md §7.2:
    SurveyLens is currently stateless (LLM proxy). Middleware attaches
    request.state.user for future use, but no per-user data model today.
    Deletion cascade endpoint: placeholder DELETE
    /api/v1/_internal/users/{user_id}/data — returns 204 immediately
    (nothing to delete). Keeps the interface uniform.

When SurveyLens grows a real user-data model (saved analyses, etc.) this
becomes a real deletion cascade like georef's. For now it just answers 204
so the IdP's cascade orchestrator can treat all three apps the same.

Bearer-token gated — the IdP holds the raw token, SurveyLens holds only the
SHA-256 hash in ``CAVEID_TO_SURVEYLENS_TOKEN_SHA256``.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Response

from cavefinder_auth import require_m2m_token

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/_internal", tags=["internal"])


@router.delete("/users/{user_id}/data", status_code=204)
def cascade_delete_user_data(
    user_id: int,
    _: None = Depends(
        require_m2m_token(expected_hash_env="CAVEID_TO_SURVEYLENS_TOKEN_SHA256")
    ),
) -> Response:
    """No-op today. Log the call so cascade orchestration is traceable."""
    log.info("Cascade delete received for user_id=%s (no-op — surveylens is stateless)", user_id)
    return Response(status_code=204)
