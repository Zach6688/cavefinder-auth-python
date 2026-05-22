"""JWT decoding + user-dict normalization.

DESIGN.md references:
  - §5.1 Access token claims (sub is a STRING per RFC 7519, but we coerce to int for
    client app convenience since CaveFinder user IDs are always integers).
  - §5.5 MUST: algorithms=['RS256'] explicit, iss check, leeway=30, fail on any error.
"""
from __future__ import annotations

from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .config import AuthConfig
from .errors import InvalidTokenError
from .jwks import JWKSCache

# §5.5 — PyJWT does NOT enforce presence of these claims by default. If a token
# arrives without ``exp`` PyJWT happily decodes it and never enforces an
# expiration. Same for ``iat`` and ``iss``. We require them explicitly so a
# malformed or maliciously-minted token can't dodge the safety net.
_REQUIRED_CLAIMS = ["exp", "iat", "iss", "sub"]


def _public_key_pem(public_key: RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _decode_options(audience: str | None) -> dict[str, object]:
    """Build the ``options`` kwarg for :func:`jwt.decode`.

    Always requires exp/iat/iss/sub. When ``audience`` is ``None`` the ``aud``
    claim is not verified (current IdP behavior — no ``aud`` is emitted yet).
    When ``audience`` is set, PyJWT's default ``verify_aud=True`` kicks in via
    the ``audience=`` kwarg passed to :func:`jwt.decode`.
    """
    options: dict[str, object] = {"require": list(_REQUIRED_CLAIMS)}
    if audience is None:
        options["verify_aud"] = False
    return options


def decode_access_token(
    token: str,
    *,
    config: AuthConfig,
    jwks_cache: JWKSCache,
) -> dict[str, Any]:
    """Decode + verify per §5.5. Returns the normalized user dict on success.

    Every failure mode — missing kid, unknown kid, bad signature, expired, wrong
    issuer, malformed JSON — raises :class:`InvalidTokenError`.
    """
    if not token:
        raise InvalidTokenError("empty token")

    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(f"malformed JWT header: {exc}") from exc

    kid = unverified_header.get("kid")
    if not kid:
        raise InvalidTokenError("JWT header missing 'kid'")

    try:
        public_key = jwks_cache.get_key(config.jwks_url, kid)
    except Exception as exc:
        # Treat any JWKS-lookup failure as token-invalid, not JWKS-down, so the
        # middleware returns 401 rather than 500. JWKSFetchError is already logged.
        raise InvalidTokenError(f"JWKS lookup failed: {exc}") from exc

    try:
        claims = jwt.decode(
            token,
            _public_key_pem(public_key),
            algorithms=["RS256"],           # §5.5 explicit
            issuer=config.issuer,            # §5.5 issuer check
            leeway=config.jwt_leeway,        # §5.5 leeway
            audience=config.audience,        # None → skipped via options below
            options=_decode_options(config.audience),
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    return claims_to_user(claims)


async def decode_access_token_async(
    token: str,
    *,
    config: AuthConfig,
    jwks_cache: JWKSCache,
) -> dict[str, Any]:
    """Async mirror of :func:`decode_access_token` — non-blocking JWKS lookup.

    Use this from ASGI middleware so a slow JWKS server can't stall the event
    loop for every concurrent request. Verification rules are identical.
    """
    if not token:
        raise InvalidTokenError("empty token")

    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(f"malformed JWT header: {exc}") from exc

    kid = unverified_header.get("kid")
    if not kid:
        raise InvalidTokenError("JWT header missing 'kid'")

    try:
        public_key = await jwks_cache.get_key_async(config.jwks_url, kid)
    except Exception as exc:
        # Treat any JWKS-lookup failure as token-invalid, not JWKS-down, so the
        # middleware returns 401 rather than 500. JWKSFetchError is already logged.
        raise InvalidTokenError(f"JWKS lookup failed: {exc}") from exc

    try:
        claims = jwt.decode(
            token,
            _public_key_pem(public_key),
            algorithms=["RS256"],           # §5.5 explicit
            issuer=config.issuer,            # §5.5 issuer check
            leeway=config.jwt_leeway,        # §5.5 leeway
            audience=config.audience,        # None → skipped via options below
            options=_decode_options(config.audience),
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    return claims_to_user(claims)


def claims_to_user(claims: dict[str, Any]) -> dict[str, Any]:
    """Normalize a decoded JWT into the shape ``request.state.user`` receives.

    Fields match those signed by the IdP in ``core/jwt_keys.sign_access_token``:
        id              — int (cast from ``sub`` string)
        email           — str
        display_name    — str
        tier            — str (one of free / pro / enterprise / etc.)
        email_verified  — bool
        is_admin        — bool
        impersonator_id — int | None (present only during impersonation; §10.16)
    """
    sub = claims.get("sub")
    if sub is None:
        raise InvalidTokenError("JWT missing 'sub'")
    try:
        user_id = int(sub)
    except (TypeError, ValueError) as exc:
        raise InvalidTokenError(f"JWT 'sub' is not an integer: {sub!r}") from exc

    return {
        "id": user_id,
        "email": claims.get("email") or "",
        "display_name": claims.get("display_name") or "",
        "tier": claims.get("tier") or "free",
        "email_verified": bool(claims.get("email_verified")),
        "is_admin": bool(claims.get("is_admin")),
        "impersonator_id": claims.get("imp"),
    }
