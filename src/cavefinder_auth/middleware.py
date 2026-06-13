"""Starlette/FastAPI middleware for CaveFinder SSO.

DESIGN.md §6.1:
    Each client app adds a middleware that:
      1. Read __Secure-cf_at cookie.
      2. Verify per §5.5.
      3. On success → populate request.state.user.
      4. On missing cookie:
           - JSON routes → 401 JSON body.
           - HTML page routes → 302 to https://id.cavefinder.app/login?return=<url>.
      5. On invalid signature → 401 always (prevents redirect loops from tampered cookies).

How we decide JSON vs HTML:
    * Any path beginning with ``/api/`` (the project's FastAPI convention) → JSON.
    * Else, look at ``Accept`` header — ``application/json`` / ``text/event-stream``
      get JSON; anything else (including ``text/html``, ``*/*``, missing) gets HTML.

Public paths (config.public_paths) bypass auth entirely — use for health checks,
static assets, and public viewer routes (e.g. georef's ``/view/:id``).
"""
from __future__ import annotations

import logging
from urllib.parse import quote

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import AuthConfig
from .errors import InvalidTokenError
from .jwks import JWKSCache
from .tokens import decode_access_token_async

log = logging.getLogger(__name__)


class AuthMiddleware:
    """ASGI middleware that enforces CaveFinder SSO on every request.

    Usage::

        app.add_middleware(
            AuthMiddleware,
            config=AuthConfig(issuer=..., jwks_url=..., login_url=...),
        )

    The ``jwks_cache`` argument is optional — the middleware creates one sized
    from the config if not provided. Tests use :func:`cavefinder_auth.testing.override_jwks`
    to inject the fixture public key.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: AuthConfig,
        jwks_cache: JWKSCache | None = None,
    ) -> None:
        self.app = app
        self.config = config
        self.jwks_cache = jwks_cache or JWKSCache(
            cache_ttl=config.jwks_cache_ttl,
            stale_ttl=config.jwks_stale_ttl,
            http_timeout=config.http_timeout,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        # Public paths (health, static, viewer) bypass auth entirely.
        #
        # Use the raw ASGI ``scope["path"]``, NOT ``request.url.path``:
        # ``request.url`` is reconstructed using the Host header, which
        # Starlette <=1.0.0 does not validate (CVE-2026-48710 "BadHost") — a
        # crafted Host header can inject a path prefix into
        # ``request.url.path``. Reading it here would let an attacker make a
        # PROTECTED route's path match a public prefix and skip auth, while
        # ASGI routing (which matches on ``scope["path"]``) still dispatches to
        # the protected handler. ``scope["path"]`` is exactly what the router
        # matches on, so the auth decision stays consistent with dispatch and
        # is immune to Host-header poisoning regardless of the Starlette
        # version. (Defense-in-depth: downstream handlers also call
        # ``current_user``, but the bypass decision must not be poisonable.)
        if self.config.is_public_path(scope["path"]):
            await self.app(scope, receive, send)
            return

        cookie = request.cookies.get(self.config.cookie_name)
        if not cookie:
            response = self._unauthenticated_response(request, missing=True)
            await response(scope, receive, send)
            return

        try:
            user = await decode_access_token_async(
                cookie, config=self.config, jwks_cache=self.jwks_cache
            )
        except InvalidTokenError as exc:
            log.warning(
                "Rejected invalid JWT for %s %s: %s",
                request.method,
                request.url.path,
                exc,
            )
            response = self._unauthenticated_response(request, missing=False)
            await response(scope, receive, send)
            return

        # Stash the user dict on request.state so downstream routes can read it.
        # Starlette's Request.state is backed by scope["state"] (a State object),
        # so setting it here persists for the duration of the request.
        request.state.user = user

        await self.app(scope, receive, send)

    # ──────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────
    def _unauthenticated_response(self, request: Request, *, missing: bool) -> Response:
        """Build the right unauthenticated response for this request.

        ``missing=True``  → no cookie at all; HTML routes get a 302 to login.
        ``missing=False`` → cookie present but invalid; always 401 (§6.1 step 6).
        """
        if self._wants_json(request) or not missing:
            return JSONResponse(
                {"error": "unauthenticated"},
                status_code=401,
            )
        # Preserve full URL (including query string) so login can bounce the user back.
        return_url = str(request.url)
        return RedirectResponse(
            f"{self.config.login_url}?return={quote(return_url, safe='')}",
            status_code=302,
        )

    @staticmethod
    def _wants_json(request: Request) -> bool:
        """True if the client is clearly an API caller, not a browser-navigation request."""
        # scope["path"], not the Host-poisonable request.url.path (CVE-2026-48710).
        if request.scope["path"].startswith("/api/"):
            return True
        accept = request.headers.get("accept", "").lower()
        if "application/json" in accept or "text/event-stream" in accept:
            return True
        # Fetch requests from our SPA set ``X-Requested-With`` — treat as JSON.
        if request.headers.get("x-requested-with", "").lower() == "fetch":
            return True
        return False


# Convenience FastAPI dependency for routes that need the current user.
def require_user(request: Request) -> dict:
    """FastAPI dependency — returns ``request.state.user`` or 401s if not present.

    Normally the middleware guarantees ``request.state.user`` exists on every
    non-public route, so this dependency only adds value on routes that were
    whitelisted as public but still want the user if one is logged in. In
    that case call :func:`optional_user` instead.
    """
    user = getattr(request.state, "user", None)
    if user is None:
        from fastapi import HTTPException  # imported lazily so the package works w/o fastapi

        raise HTTPException(status_code=401, detail="unauthenticated")
    return user


def optional_user(request: Request) -> dict | None:
    """FastAPI dependency — returns the user dict if present, else None."""
    return getattr(request.state, "user", None)
