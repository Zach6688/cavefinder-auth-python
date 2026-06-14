"""Starlette/FastAPI middleware for CaveFinder SSO.

DESIGN.md §6.1:
    Each client app adds a middleware that:
      1. Read __Secure-cf_at cookie.
      2. Verify per §5.5.
      3. On success → populate request.state.user (for HTTP) or scope["user"]
         (for WebSocket).
      4. On missing cookie:
           - JSON routes → 401 JSON body.
           - HTML page routes → 302 to https://id.cavefinder.app/login?return=<url>.
           - WebSocket → close with code 4401 (custom per RFC 6455) before the
             handshake completes.
      5. On invalid signature → 401 for HTTP, 4401 close for WebSocket.
         (Prevents redirect loops from tampered cookies; prevents an attacker
         from holding a socket open with a bad token.)

How we decide JSON vs HTML (HTTP only):
    * Any path beginning with ``/api/`` (the project's FastAPI convention) → JSON.
    * Else, look at ``Accept`` header — ``application/json`` / ``text/event-stream``
      get JSON; anything else (including ``text/html``, ``*/*``, missing) gets HTML.

WebSocket auth (OBS-2 closure):
    The middleware now intercepts `scope["type"] == "websocket"` too. Cookie
    extraction + verification reuse the HTTP path; on success we stash the
    user dict on scope["user"] AND on the Request-like wrapper so endpoints
    can read `websocket.scope["user"]` or `websocket.state.user` (Starlette
    WebSocket exposes both). On failure we emit a websocket.close ASGI
    message with code 4401 — this rejects the handshake cleanly and the
    browser Client sees a WebSocket `close` event with that code, which
    downstream client code can distinguish from a generic 1006.

Public paths (config.public_paths) bypass auth entirely — use for health checks,
static assets, public viewer routes (e.g. georef's ``/view/:id``), and any
WebSocket paths that are legitimately public (e.g. real-time map tile
streams). Whitelisting a WebSocket path is an explicit security decision:
the middleware won't guess.
"""
from __future__ import annotations

import logging
from urllib.parse import quote

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import AuthConfig
from .errors import InvalidTokenError
from .jwks import JWKSCache
from .tokens import decode_access_token

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
        scope_type = scope.get("type")
        if scope_type == "http":
            await self._handle_http(scope, receive, send)
            return
        if scope_type == "websocket":
            await self._handle_websocket(scope, receive, send)
            return
        # Lifespan (startup/shutdown) and anything exotic pass through — they
        # don't carry user identity.
        await self.app(scope, receive, send)

    async def _handle_http(
        self, scope: Scope, receive: Receive, send: Send,
    ) -> None:
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
        # matches on (the WebSocket handler below already keys on it), so the
        # auth decision stays consistent with dispatch and is immune to
        # Host-header poisoning regardless of the Starlette version.
        if self.config.is_public_path(scope["path"]):
            await self.app(scope, receive, send)
            return

        cookie = request.cookies.get(self.config.cookie_name)
        if not cookie:
            response = self._unauthenticated_response(request, missing=True)
            await response(scope, receive, send)
            return

        try:
            user = decode_access_token(cookie, config=self.config, jwks_cache=self.jwks_cache)
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

    async def _handle_websocket(
        self, scope: Scope, receive: Receive, send: Send,
    ) -> None:
        """Enforce the same cookie auth on WebSocket handshakes.

        Public WebSocket paths (via config.public_paths) bypass auth — this
        covers future "public map tile stream" style routes.

        On missing or invalid cookie we send a `websocket.close` ASGI message
        with code 4401 BEFORE the handshake completes. Per ASGI spec, the
        client sees the close cleanly and no `websocket.connect` is ever
        delivered to the app — the route handler isn't reachable.
        """
        path = scope.get("path", "")
        if self.config.is_public_path(path):
            await self.app(scope, receive, send)
            return

        cookie = _cookie_from_scope(scope, self.config.cookie_name)
        if not cookie:
            log.info("Rejecting websocket connect for %s: no cookie", path)
            await _ws_close_with_code(send, code=4401)
            return

        try:
            user = decode_access_token(
                cookie, config=self.config, jwks_cache=self.jwks_cache,
            )
        except InvalidTokenError as exc:
            log.warning("Rejected invalid JWT for ws %s: %s", path, exc)
            await _ws_close_with_code(send, code=4401)
            return

        # Expose the user to the route handler via both conventions so
        # endpoints can read from whichever they prefer:
        #   async def ws(websocket: WebSocket):
        #       user = websocket.scope["user"]
        #       # or
        #       user = websocket.state.user
        scope["user"] = user
        state = scope.setdefault("state", {})
        # Starlette's State wraps a dict; for scope-level injection the
        # plain dict works because State(scope["state"]) just reads/writes it.
        if isinstance(state, dict):
            state["user"] = user

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


def _cookie_from_scope(scope: Scope, cookie_name: str) -> str | None:
    """Extract a single cookie from a raw ASGI scope without building a Request.

    WebSocket scopes don't expose a `.cookies` dict directly; we walk the raw
    headers and parse the `cookie` header ourselves. Parsing is deliberately
    minimal (split on `;`, trim, split on first `=`) — the http.cookies
    module would be stricter but adds a dep and handles quoted values we
    don't emit.
    """
    raw_headers = scope.get("headers") or ()
    for raw_name, raw_value in raw_headers:
        if raw_name == b"cookie":
            try:
                header = raw_value.decode("latin-1")
            except UnicodeDecodeError:
                return None
            for piece in header.split(";"):
                piece = piece.strip()
                if not piece or "=" not in piece:
                    continue
                name, _, value = piece.partition("=")
                if name.strip() == cookie_name:
                    return value.strip()
    return None


async def _ws_close_with_code(send: Send, *, code: int) -> None:
    """Close a WebSocket before the handshake completes with a custom code.

    Per ASGI, emitting `websocket.close` before `websocket.accept` rejects
    the handshake — the HTTP response becomes 403 from the server's POV and
    the browser `WebSocket` constructor fires a `close` event with the code
    we pass. 4401 is the standard convention for "unauthorized" in the
    private-use close-code range (4000–4999 per RFC 6455 §7.4.2).
    """
    message: Message = {"type": "websocket.close", "code": code}
    await send(message)


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
