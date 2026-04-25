"""Simplified auth Blueprint for cavefinder.

DESIGN.md §7.3 mandates that cavefinder's `auth.py` be drastically simplified:
the full register/login/reset/change-email surface moves to the IdP. What
remains here is:
  * Browser-navigation redirects to the IdP for login/register/reset pages
  * A /logout that clears the local state + proxies to the IdP's logout
  * /api/userinfo — a pass-through that fetches from the IdP for the SPA's
    "who am I" call. (Alternatively the SPA can call the IdP directly; this
    keeps the option open.)

All admin routes, promo-code routes, tier-override routes, user-list routes —
DELETED. Those live on the IdP at /admin/* now. Do not re-add them here.

Drop this file into cavefinder's backend as a replacement for the existing
auth.py Blueprint. The Flask session cookie is no longer used for identity —
delete any `session['user_id']` references in the rest of the codebase.
"""
from __future__ import annotations

import os
from urllib.parse import quote

import httpx
from flask import Blueprint, jsonify, redirect, request

from flask_auth import current_user


auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _idp_base() -> str:
    return os.environ.get("CAVEID_ISSUER", "https://id.cavefinder.app")


def _return_url() -> str:
    """Where to bounce the user after they finish on the IdP.

    Prefer the ``next`` query param if present (validated below), else the
    Referer, else the cavefinder root. NEVER accept an off-site next — that's
    a classic open-redirect bug.
    """
    candidate = request.args.get("next") or request.headers.get("Referer") or "/"
    # Only accept same-origin (path-only) or explicitly cavefinder.app URLs.
    # An attacker-controlled ``next`` that starts with ``https://evil.com`` must
    # be discarded — if we blindly pass it through, the IdP's login-success
    # redirect sends the user to evil.com with no cookie (low-severity phish
    # surface, but still worth closing).
    if candidate.startswith("/"):
        return f"https://cavefinder.app{candidate}"
    if candidate.startswith("https://cavefinder.app"):
        return candidate
    return "https://cavefinder.app/"


@auth_bp.route("/login", methods=["GET"])
def login():
    return redirect(f"{_idp_base()}/login?return={quote(_return_url(), safe='')}", code=302)


@auth_bp.route("/register", methods=["GET"])
def register():
    return redirect(f"{_idp_base()}/register?return={quote(_return_url(), safe='')}", code=302)


@auth_bp.route("/forgot-password", methods=["GET"])
def forgot():
    return redirect(f"{_idp_base()}/forgot-password", code=302)


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Proxy to the IdP's logout.

    The IdP clears __Secure-cf_at + __Secure-cf_rt cookies for Domain=cavefinder.app
    which kills the session on every subdomain (cavefinder, id, georef, surveylens)
    at once. No local state to clear here because cavefinder no longer stores
    identity in a local session.
    """
    # Returning a redirect lets the SPA follow it from its logout handler.
    return redirect(f"{_idp_base()}/logout", code=302)


@auth_bp.route("/userinfo", methods=["GET"])
def userinfo():
    """Pass-through to ``id.cavefinder.app/api/userinfo``.

    This endpoint exists so the SPA doesn't need a CORS exception to fetch the
    IdP directly. It forwards the user's cookies and returns the IdP's JSON
    verbatim. If the caller isn't logged in, return 401 without touching the
    IdP (saves a round-trip).
    """
    if current_user() is None:
        return jsonify({"error": "unauthenticated"}), 401
    try:
        resp = httpx.get(
            f"{_idp_base()}/api/userinfo",
            cookies=request.cookies,
            timeout=3.0,
        )
    except httpx.HTTPError:
        return jsonify({"error": "idp_unreachable"}), 503
    return (resp.content, resp.status_code, {"Content-Type": resp.headers.get("content-type", "application/json")})
