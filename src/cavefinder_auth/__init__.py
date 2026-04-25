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

__version__ = "0.1.0"

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
