"""cavefinder-auth — shared SSO client for CaveFinder IdP.

Public API. Internal modules (jwks, tokens) are importable but not part of
the stability contract — use the re-exports below.
"""
from __future__ import annotations

from .config import AuthConfig
from .errors import (
    CavefinderAuthError,
    InvalidTokenError,
    JWKSFetchError,
    M2MAuthError,
    MissingCookieError,
)
from .jwks import JWKSCache
from .m2m import extract_bearer_token, hash_token, require_m2m_token, verify_m2m_token
from .middleware import AuthMiddleware, optional_user, require_user
from .tokens import decode_access_token
from .userinfo import (
    SyncUserinfoClient,
    UserinfoClient,
    get_user_tier,
    get_user_tier_sync,
)

__version__ = "0.2.5"

__all__ = [
    "__version__",
    # Config + middleware
    "AuthConfig",
    "AuthMiddleware",
    "require_user",
    "optional_user",
    # Token/JWKS primitives (advanced use)
    "decode_access_token",
    "JWKSCache",
    # Live userinfo client (Phase 1 — sole tier source-of-truth)
    "UserinfoClient",
    "SyncUserinfoClient",
    "get_user_tier",
    "get_user_tier_sync",
    # M2M helpers
    "require_m2m_token",
    "verify_m2m_token",
    "extract_bearer_token",
    "hash_token",
    # Errors
    "CavefinderAuthError",
    "InvalidTokenError",
    "JWKSFetchError",
    "M2MAuthError",
    "MissingCookieError",
]
