"""Exception hierarchy for cavefinder-auth.

DESIGN.md references:
  - §5.5 JWT verification — invalid sig / issuer / expiry map to distinct errors
    so middleware can tell "never logged in" (no cookie) from "tampered cookie"
    (InvalidTokenError) and respond accordingly.
"""
from __future__ import annotations


class CavefinderAuthError(Exception):
    """Base class for every auth error this package raises."""


class MissingCookieError(CavefinderAuthError):
    """No __Secure-cf_at cookie on the request. Maps to 401 (JSON) or 302 (HTML)."""


class InvalidTokenError(CavefinderAuthError):
    """Signature mismatch, wrong issuer, expired, malformed. Always 401 — never 302."""


class JWKSFetchError(CavefinderAuthError):
    """Could not fetch the JWKS document and no cached copy is available.

    Raised only when both:
      - The in-memory cache is empty (first-ever fetch), AND
      - The stale-if-error window has expired (> 24 h since last good fetch).
    """


class M2MAuthError(CavefinderAuthError):
    """Machine-to-machine token missing or invalid. Maps to 401."""
