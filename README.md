# cavefinder-auth

Shared JWT verification library for **CaveFinder Identity Provider** (`id.cavefinder.app`) client apps.

This package is imported by every app behind the CaveFinder SSO — `cavefinder`, `cave-georef`, `surveylens` — so we don't reimplement JWKS caching, RS256 verification, or the login-redirect dance three times. See `cave-id/DESIGN.md` §6.1 and §7 for the contract.

## Quickstart

```python
from fastapi import FastAPI, Request
from cavefinder_auth import AuthConfig, AuthMiddleware

app = FastAPI()
app.add_middleware(
    AuthMiddleware,
    config=AuthConfig(
        issuer="https://id.cavefinder.app",
        jwks_url="https://id.cavefinder.app/.well-known/jwks.json",
        login_url="https://id.cavefinder.app/login",
        # Optional: paths that skip auth entirely (health checks, static, public viewer, etc.)
        public_paths=("/api/healthz", "/static", "/view"),
    ),
)

@app.get("/api/me")
def me(request: Request):
    user = request.state.user
    return {"id": user["id"], "email": user["email"], "tier": user["tier"]}
```

## What the middleware does

1. Reads the `__Secure-cf_at` cookie.
2. Fetches JWKS from the IdP (cached 1 h; stale-if-error up to 24 h).
3. Verifies the JWT with `algorithms=["RS256"]`, `iss` check, 30 s leeway.
4. Populates `request.state.user = {id, email, display_name, tier, email_verified, is_admin, impersonator_id}`.
5. On **missing cookie**:
   - JSON routes → `401 {"error": "unauthenticated"}`
   - HTML routes → `302 Location: <login_url>?return=<current_url>`
6. On **invalid signature / expired / wrong issuer**: always `401`, never `302` (prevents redirect loops from tampered cookies).

## M2M endpoints

For `/api/v1/_internal/...` routes (deletion cascade, Stripe forwarding) the IdP authenticates with a bearer token. Use the `require_m2m_token` dependency:

```python
from cavefinder_auth import require_m2m_token

@app.delete("/api/v1/_internal/users/{user_id}/data")
def cascade_delete(
    user_id: int,
    _: None = Depends(require_m2m_token(expected_hash_env="CAVEID_TO_GEOREF_TOKEN_SHA256")),
):
    ...
```

## Testing helpers

```python
from cavefinder_auth.testing import (
    generate_test_keypair,
    make_test_jwt,
    override_jwks,
    client_with_user,
)

def test_me_endpoint(app):
    keypair = generate_test_keypair()
    override_jwks(app, keypair.public)
    client = client_with_user(app, keypair=keypair, user_id=42, email="a@b.com", tier="pro")
    resp = client.get("/api/me")
    assert resp.status_code == 200
```

## License

Internal use only. Not published to PyPI.
