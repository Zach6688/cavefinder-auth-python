"""Flask adapter for CaveFinder Identity Provider.

Cavefinder is a Flask app, so the Starlette-based ``AuthMiddleware`` from
cavefinder-auth doesn't apply directly. This module wires the framework-agnostic
primitives (``JWKSCache``, ``decode_access_token``, ``verify_m2m_token``) into
Flask's ``before_request`` hook + decorator pattern.

Drop into ``cavefinder/backend/flask_auth.py`` and register in the app factory::

    from flask_auth import init_auth, login_required, require_m2m_token_flask

    def create_app():
        app = Flask(__name__)
        init_auth(app)   # registers before_request hook
        return app

    @app.route("/api/me")
    @login_required
    def me():
        return jsonify(g.user)

DESIGN.md §7.3:
    ``_current_user()`` is rewritten to read from
    ``request.cookies.get('__Secure-cf_at')``, verify, return user info.
"""
from __future__ import annotations

import logging
import os
from functools import wraps
from typing import Any
from urllib.parse import quote

from flask import Flask, abort, current_app, g, jsonify, redirect, request, session

from cavefinder_auth import (
    AuthConfig,
    InvalidTokenError,
    JWKSCache,
    JWKSFetchError,
    decode_access_token,
    extract_bearer_token,
    verify_m2m_token,
)

log = logging.getLogger(__name__)


def _build_config() -> AuthConfig:
    issuer = os.environ.get("CAVEID_ISSUER", "https://id.cavefinder.app")
    return AuthConfig(
        issuer=issuer,
        jwks_url=os.environ.get("CAVEID_JWKS_URL", f"{issuer}/.well-known/jwks.json"),
        login_url=os.environ.get("CAVEID_LOGIN_URL", f"{issuer}/login"),
    )


def init_auth(app: Flask) -> None:
    """Wire up cookie reading + user-dict population on every request.

    After this runs, every handler can read ``g.user`` — either a dict with the
    shape from §5.1, or ``None`` for anonymous requests. Routes that require
    auth use ``@login_required``; public routes (marketing pages, Stripe webhooks,
    the cascade endpoint) simply don't.

    The JWKS cache is stored on ``app.extensions['cavefinder_auth']`` so it
    persists across requests (one per process).
    """
    config = _build_config()
    cache = JWKSCache(
        cache_ttl=config.jwks_cache_ttl,
        stale_ttl=config.jwks_stale_ttl,
        http_timeout=config.http_timeout,
    )
    app.extensions.setdefault("cavefinder_auth", {"config": config, "cache": cache})

    @app.before_request
    def _load_user() -> None:
        cookie = request.cookies.get(config.cookie_name)
        if not cookie:
            g.user = None
            return
        try:
            g.user = decode_access_token(cookie, config=config, jwks_cache=cache)
        except InvalidTokenError as exc:
            log.warning("Rejected invalid JWT on %s: %s", request.path, exc)
            g.user = None
            return
        except JWKSFetchError as exc:
            # Network blip / IdP momentarily unreachable / cold cache after deploy.
            # Treat as anonymous rather than 500'ing every request from a
            # cf_at-bearing user. JWKSCache's stale-if-error window (24h)
            # absorbs longer outages once JWKS has been fetched at least once.
            log.warning("JWKS fetch failed on %s: %s — treating request as anonymous", request.path, exc)
            g.user = None
            return

        # Phase 1 hybrid bridge: propagate the JWT-resolved user into the
        # legacy Flask session so existing ``session.get('user_id')`` reads
        # in retrofitted apps pick up JWT-authenticated users without
        # touching every call site. Retire this bridge once the legacy
        # session-based login flow is removed entirely.
        if g.user and session.get("user_id") != g.user["id"]:
            session["user_id"] = g.user["id"]


def login_required(fn):
    """Flask decorator — 401 JSON for API routes, 302 to IdP login for HTML.

    The "HTML vs JSON" rule mirrors the Starlette middleware: paths under
    ``/api/`` always get JSON, otherwise honor the ``Accept`` header.
    """
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        if getattr(g, "user", None) is None:
            return _unauthorized_response()
        return fn(*args, **kwargs)

    return wrapper


def _unauthorized_response():
    config = _get_config()
    if _wants_json():
        return jsonify({"error": "unauthenticated"}), 401
    return_url = request.url
    return redirect(f"{config.login_url}?return={quote(return_url, safe='')}", code=302)


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    accept = request.headers.get("Accept", "").lower()
    if "application/json" in accept or "text/event-stream" in accept:
        return True
    if request.headers.get("X-Requested-With", "").lower() == "fetch":
        return True
    return False


def _get_config() -> AuthConfig:
    return current_app.extensions["cavefinder_auth"]["config"]


# ──────────────────────────────────────────────────────────────
# Machine-to-machine bearer auth for cascade endpoint
# ──────────────────────────────────────────────────────────────
def require_m2m_token_flask(env_var: str):
    """Decorator factory — 401s unless Authorization: Bearer matches env_var's hash.

    Usage::

        @app.route("/api/v1/_internal/users/<int:user_id>/data", methods=["DELETE"])
        @require_m2m_token_flask("CAVEID_TO_CAVEFINDER_TOKEN_SHA256")
        def cascade_delete(user_id: int):
            ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            expected = os.environ.get(env_var, "")
            if not expected:
                log.error("M2M service token env var %s is not set — rejecting request", env_var)
                abort(401)
            raw = extract_bearer_token(request)
            if not raw or not verify_m2m_token(raw, expected):
                abort(401)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ──────────────────────────────────────────────────────────────
# Convenience accessor for handlers that want the authenticated user
# ──────────────────────────────────────────────────────────────
def current_user() -> dict | None:
    """Return g.user if authenticated, else None."""
    return getattr(g, "user", None)


def current_user_id() -> int:
    """Return the authenticated user's integer ID, or raise 401 if not logged in."""
    user = current_user()
    if user is None:
        abort(401)
    return int(user["id"])
