# SurveyLens retrofit kit

Drop-in files to add CaveFinder SSO to the SurveyLens FastAPI app.

Per `cave-id/DESIGN.md` §7.2, SurveyLens is currently stateless (an LLM proxy)
so the retrofit has only two required pieces:

1. **JWT middleware** — every request gets `request.state.user` populated.
2. **Cascade endpoint stub** — `DELETE /api/v1/_internal/users/{id}/data`
   returns 204 immediately (nothing to delete). Keeps the inter-service
   interface uniform so the IdP's cascade orchestrator doesn't need a special
   case.

## Apply

1. Add `cavefinder-auth>=0.1` to `requirements.txt`.
2. Copy `main_patch.py` contents into the top of `main.py` (or wherever the
   FastAPI app is instantiated), replacing the `# TODO: auth` area.
3. Copy `api/internal.py` into the project under the same path; register its
   router in `main.py`.
4. Set these env vars in the container:
   - `CAVEID_ISSUER=https://id.cavefinder.app`
   - `CAVEID_JWKS_URL=https://id.cavefinder.app/.well-known/jwks.json`
   - `CAVEID_LOGIN_URL=https://id.cavefinder.app/login`
   - `CAVEID_TO_SURVEYLENS_TOKEN_SHA256=<sha256 hex of the shared secret>`
5. Copy `conftest_patch.py` content into the test suite's conftest (or merge
   with an existing one).

That's the whole retrofit — SurveyLens has no per-user data today so there's
nothing to filter or scope. When saved-analyses arrive later, add
`owner_user_id` to the model and follow the pattern from the georef retrofit.

## Deploy order

Per DESIGN §8 the cutover deploys IdP → georef → surveylens → cavefinder. Never
deploy surveylens before the IdP is live — the middleware will fail stale-if-error
within 24 h if JWKS was ever cached, but a brand-new deploy with no cache will
reject every request.

## Rollback

Revert the middleware registration and remove the `CAVEID_*` env vars. The app
reverts to unauthenticated (its pre-cutover state). The cascade endpoint can
stay — it's a no-op if no calls come in.

## Monitoring

Watch for log lines tagged `cavefinder_auth.middleware` — a burst of
`Rejected invalid JWT` warnings after a deploy usually means a cookie-domain
misconfiguration on the IdP side. JWKS-fetch failures log as
`cavefinder_auth.jwks` warnings with the stale-cache age.
