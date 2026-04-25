"""Paste this block into SurveyLens's main.py (or equivalent) at FastAPI-init time.

Before:
    from fastapi import FastAPI
    app = FastAPI()

After:
    (this file's contents)
"""
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from cavefinder_auth import AuthConfig, AuthMiddleware

# Import the cascade stub router — see api/internal.py in this kit.
from api.internal import router as internal_router


app = FastAPI(title="SurveyLens", version="1.0")


# ── Env-driven auth config ────────────────────────────────────────────────────
_ISSUER = os.environ.get("CAVEID_ISSUER", "https://id.cavefinder.app")
_JWKS_URL = os.environ.get("CAVEID_JWKS_URL", f"{_ISSUER}/.well-known/jwks.json")
_LOGIN_URL = os.environ.get("CAVEID_LOGIN_URL", f"{_ISSUER}/login")


auth_config = AuthConfig(
    issuer=_ISSUER,
    jwks_url=_JWKS_URL,
    login_url=_LOGIN_URL,
    public_paths=(
        "/api/health",           # uptime probes
        "/api/v1/_internal",     # cascade endpoint (M2M bearer, not cookie)
    ),
)

# Auth must run BEFORE CORS in the request pipeline, which means we register it
# LAST (Starlette runs middleware in reverse registration order).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://cavefinder.app", "https://id.cavefinder.app"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.add_middleware(AuthMiddleware, config=auth_config)


app.include_router(internal_router)

# … keep existing surveylens routers (llm_proxy, uploads, analyses, etc.) below
# this line. Their handlers can now read request.state.user to get the
# authenticated caller when needed — no change required if the route doesn't
# need the user yet (the middleware just attaches it).
