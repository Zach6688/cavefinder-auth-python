# Cavefinder Retrofit Kit

Drop-in scaffolding that converts the existing **cavefinder.app** Flask backend
from "identity-owning monolith" into a pure **relying party** against the
CaveFinder Identity Provider (`id.cavefinder.app`).

This is the reference implementation referenced in `DESIGN.md §7.3` and `§8`.
Copy each file into the cavefinder repo at the path noted below, swap the
existing equivalent, and run the retrofit tests.

```
examples/cavefinder_retrofit/
├── backend/
│   ├── flask_auth.py            → cavefinder/backend/flask_auth.py
│   ├── auth_blueprint.py        → cavefinder/backend/routes/auth.py   (REPLACES existing)
│   ├── internal_blueprint.py    → cavefinder/backend/routes/internal.py
│   └── stripe_forwarder.py      → cavefinder/backend/integrations/stripe_forwarder.py
├── migrations/
│   └── split_cavefinder_user_usage.py     (cavefinder-side — run step 3 of §8 cutover)
└── tests/
    ├── test_flask_auth.py       (9 tests — @login_required + @require_m2m_token_flask)
    └── test_migrations.py       (4 tests — split + preflight)

# Canonical IdP-side migrations live with the IdP:
#   cave-id/backend/scripts/migrate_users_to_idp.py          (step 6 of §8 cutover)
#   cave-id/backend/scripts/restore_users_to_cavefinder.py   (rollback, hopefully never run)
# Their tests live in cave-id/backend/tests/.
```

**Test status:** 13/13 passing in ~1s (9 Flask auth + 4 split-usage).
IdP-side migration tests live in `cave-id/backend/tests/`.

---

## 1. What changes in cavefinder

| Before                                             | After                                                       |
|----------------------------------------------------|-------------------------------------------------------------|
| `users` table with password_hash, verification codes, Stripe fields, daily_scans_* | `user_usage` table only; identity moves to IdP               |
| `/api/auth/register`, `/login`, `/forgot-password` | Redirects to IdP (`auth_blueprint.py`)                      |
| `_current_user()` reads session cookie             | `g.user` populated by `flask_auth.init_auth()` `before_request` |
| Stripe webhook updates local users table           | Webhook forwards to `id.cavefinder.app/api/admin/update-tier` |
| — (no equivalent)                                  | `DELETE /api/v1/_internal/users/<id>/data` cascade endpoint |

## 2. Env vars the cavefinder container needs

```env
# Issued by the IdP — verify JWT and redirect anonymous visitors.
CAVEID_ISSUER=https://id.cavefinder.app
CAVEID_JWKS_URL=https://id.cavefinder.app/.well-known/jwks.json
CAVEID_LOGIN_URL=https://id.cavefinder.app/login

# Cavefinder → IdP: Stripe webhook forwarding. Hold the RAW token.
CAVEID_SERVICE_TOKEN=<raw-m2m-token>

# IdP → Cavefinder: cascade delete. Hold only the SHA-256 HEX DIGEST here.
CAVEID_TO_CAVEFINDER_TOKEN_SHA256=<sha256-hex-of-raw>
```

The raw cascade token lives on the IdP. Cavefinder only ever sees the hash,
so a DB leak here doesn't let the attacker impersonate the IdP.

## 3. App-factory wiring

```python
# cavefinder/backend/app.py
from flask import Flask
from flask_auth import init_auth
from routes.auth import auth_bp
from routes.internal import internal_bp

def create_app():
    app = Flask(__name__)
    init_auth(app)                       # before_request: populate g.user
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(internal_bp)  # already namespaced at /api/v1/_internal
    return app
```

## 4. Migration order (follows `DESIGN.md §8`)

1. Deploy IdP behind a feature flag — no cavefinder changes yet.
2. Dry-run `migrations/split_cavefinder_user_usage.py --db /opt/cavefinder/users.db --dry-run`.
3. Run the split for real. `user_usage` now mirrors `daily_scans_*` columns.
4. Dry-run the IdP's copy:
   `cave-id/backend/scripts/migrate_users_to_idp.py --source <cf-db-copy> --target <idp-db> --dry-run`
   against a read-only cavefinder DB snapshot. Fix any preflight failures
   (case-conflicting emails, NULL password hashes).
5. Cutover night: take cavefinder read-only, re-run `split` then the IdP's
   `migrate_users_to_idp.py` for real.
6. Flip the frontend to the new SPA build (see `frontend_patch.md`).
7. Flip the backend to this retrofit kit. `users` table becomes orphaned.
8. Soak for 48 hours.
9. Drop the `daily_scans_*` columns from cavefinder's users table
   (leaves a vestigial `users` table — planned to drop entirely in Week 4).

**Rollback:** `cave-id/backend/scripts/restore_users_to_cavefinder.py`
reverses step 5 — reads the IdP users.db read-only, rejoins `user_usage`,
and upserts into cavefinder's users table. Re-adds any dropped columns via
`ALTER TABLE`.

## 5. Running the tests

```bash
cd examples/cavefinder_retrofit
python -m pytest tests/ -v
# 22 passed in ~1s
```

## 6. Frontend snippets

See `frontend_patch.md` in this directory.

## 7. Sharp edges

- **Daily-scan counter clock:** `user_usage.daily_scans_date` is stored as
  `YYYY-MM-DD` in **cave local time (America/New_York)**. The reset job in
  `cavefinder/jobs/reset_daily_scans.py` must be run in that tz, not UTC,
  or users get 8 hours of extra scans at midnight EST.
- **`jobs.user_id` anonymization sentinel:** the cascade endpoint sets
  orphaned job rows to `user_id = -1` (DELETE_USER_SENTINEL_ID). Any report
  that groups by `user_id` should filter that out.
- **Stripe idempotency:** `stripe_event_id` is the cross-service idempotency
  key — without it, a Stripe webhook retry would double-bill or double-grant.
  Don't remove it from the payload in `stripe_forwarder.py`.
- **Open-redirect guard:** `auth_blueprint._return_url()` validates that any
  `?next=` param is path-only or points to `cavefinder.app`. Don't relax that
  without a threat review.
