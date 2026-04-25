"""Cascade-delete Blueprint for cavefinder.

DESIGN.md §7.3 + §10.3:
    DELETE /api/v1/_internal/users/{user_id}/data on cavefinder. Deletes
    saved_results, user_usage, and any other user-owned rows. Called by IdP
    on account deletion.

Design notes:
  * Uses the M2M bearer token (CAVEID_TO_CAVEFINDER_TOKEN_SHA256), not a user cookie.
  * Uses a single DB transaction so the cascade is all-or-nothing. A partial
    cascade (saved_results deleted, user_usage not) would leave orphaned rows
    that the nightly reconciliation job (§10.4) would then try to delete and
    log — ugly, hard to debug.
  * The ``jobs`` table is soft-anonymized rather than deleted — DESIGN §10.3
    implies job-run history is part of analytics and has legitimate retention
    value. Swap the user_id to a sentinel ``DELETED_USER_SENTINEL_ID`` so
    analytics rollups still work but no personal reference remains.
"""
from __future__ import annotations

import logging
import sqlite3

from flask import Blueprint, current_app, jsonify

from flask_auth import require_m2m_token_flask

log = logging.getLogger(__name__)

internal_bp = Blueprint("internal", __name__, url_prefix="/api/v1/_internal")


# Sentinel user_id used when anonymizing historical rows we want to keep.
DELETED_USER_SENTINEL_ID = -1


@internal_bp.route("/users/<int:user_id>/data", methods=["DELETE"])
@require_m2m_token_flask("CAVEID_TO_CAVEFINDER_TOKEN_SHA256")
def cascade_delete(user_id: int):
    """Delete all cavefinder-local data for the given user.

    Returns a JSON summary of rows touched per table so the IdP's cascade
    orchestrator can audit the result. On any SQL error the transaction is
    rolled back and we return 500 — the IdP will retry (with the idempotent
    replay guard on its side preventing double-cascade).
    """
    if user_id == DELETED_USER_SENTINEL_ID:
        return jsonify({"error": "refusing to cascade on sentinel id"}), 400

    db_path = current_app.config["USERS_DB_PATH"]
    counts: dict[str, int] = {}
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.cursor()

            cur.execute("DELETE FROM saved_results WHERE user_id = ?", (user_id,))
            counts["saved_results"] = cur.rowcount

            cur.execute("DELETE FROM user_usage WHERE user_id = ?", (user_id,))
            counts["user_usage"] = cur.rowcount

            # Anonymize job history rather than delete — analytics rollups still
            # want the row counts, just not the user_id pointing to a dead user.
            cur.execute(
                "UPDATE jobs SET user_id = ? WHERE user_id = ?",
                (DELETED_USER_SENTINEL_ID, user_id),
            )
            counts["jobs_anonymized"] = cur.rowcount

            conn.commit()
    except sqlite3.DatabaseError as exc:
        log.exception("Cascade delete failed for user_id=%s: %s", user_id, exc)
        return jsonify({"error": "cascade_failed"}), 500

    log.info("Cascade-deleted cavefinder data for user_id=%s: %s", user_id, counts)
    return jsonify({"user_id": user_id, "deleted": counts}), 200
