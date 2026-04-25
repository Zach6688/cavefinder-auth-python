"""Client configuration.

DESIGN.md references:
  - §5.1 Cookie name __Secure-cf_at
  - §6.1 JWKS cache 1 h TTL, stale-if-error 24 h
  - §5.5 Issuer check mandatory, 30 s leeway
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ── Defaults taken directly from DESIGN.md so client apps don't have to repeat them. ──
DEFAULT_COOKIE_NAME = "__Secure-cf_at"
DEFAULT_JWKS_CACHE_TTL = 3600         # §6.1 — 1 hour fresh
DEFAULT_JWKS_STALE_TTL = 86400        # §6.1 — 24 hours stale-if-error
DEFAULT_JWT_LEEWAY = 30               # §5.5 — 30 seconds
DEFAULT_HTTP_TIMEOUT = 5.0            # Seconds; fail fast to avoid tying up a request


@dataclass(frozen=True)
class AuthConfig:
    """Everything a client app needs to verify JWTs and redirect to the IdP.

    ``issuer``
        Exact string that must appear in the JWT ``iss`` claim. Usually
        ``https://id.cavefinder.app``.

    ``jwks_url``
        Full URL of the IdP's JWKS endpoint
        (``https://id.cavefinder.app/.well-known/jwks.json``).

    ``login_url``
        Where HTML routes redirect unauthenticated users. The current URL is
        appended as a ``?return=...`` query param.

    ``cookie_name``
        Usually ``__Secure-cf_at``. Overridable for tests.

    ``public_paths``
        Tuple of path prefixes that skip auth entirely (health checks, static
        asset routes, public viewer pages). Matched with ``str.startswith``.

    ``jwks_cache_ttl`` / ``jwks_stale_ttl``
        Seconds. See §6.1 — fresh 1 h, stale-if-error 24 h.

    ``jwt_leeway``
        Seconds of clock drift tolerated on ``exp`` / ``iat``. Default 30.

    ``http_timeout``
        Timeout for the JWKS fetch. Kept deliberately short — stale cache is
        better than a 30 s hang on every incoming request.
    """

    issuer: str
    jwks_url: str
    login_url: str
    cookie_name: str = DEFAULT_COOKIE_NAME
    public_paths: tuple[str, ...] = field(default_factory=tuple)
    jwks_cache_ttl: int = DEFAULT_JWKS_CACHE_TTL
    jwks_stale_ttl: int = DEFAULT_JWKS_STALE_TTL
    jwt_leeway: int = DEFAULT_JWT_LEEWAY
    http_timeout: float = DEFAULT_HTTP_TIMEOUT

    def is_public_path(self, path: str) -> bool:
        """True if the request path should skip auth entirely."""
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.public_paths)
