"""Stripe webhook → IdP forwarder.

DESIGN.md §7.3:
    Stripe webhook stays at cavefinder.app/api/payments/webhook. On
    checkout.session.completed, cavefinder calls
    POST https://id.cavefinder.app/api/admin/update-tier
    X-Service-Token: <from CAVEID_SERVICE_TOKEN env>

The IdP stores the raw token's SHA-256 hash in its ``service_tokens`` table
(name ``cavefinder-m2m``). Cavefinder holds the raw token in
``CAVEID_SERVICE_TOKEN``.

Integration into cavefinder's existing webhook handler — replace any code that
previously updated the local ``users`` table on subscription change with a
call to :func:`forward_subscription_update`.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

log = logging.getLogger(__name__)

_IDP_UPDATE_TIER_URL = (
    f"{os.environ.get('CAVEID_ISSUER', 'https://id.cavefinder.app')}/api/admin/update-tier"
)


class IdPForwardError(Exception):
    """Raised when the IdP rejects or can't be reached. Stripe retries on 5xx."""


def forward_subscription_update(
    *,
    user_id: int,
    tier: str,
    stripe_subscription_id: str | None,
    stripe_customer_id: str | None,
    stripe_event_id: str,
    subscription_status: str | None = None,
    subscription_plan: str | None = None,
    subscription_ends_at: int | None = None,
    timeout_s: float = 10.0,
) -> dict[str, Any]:
    """POST the subscription update to the IdP. Return the IdP's JSON response.

    ``stripe_event_id`` is the critical idempotency key — the IdP's
    ``processed_stripe_events`` table will silently accept a duplicate call
    and return 200 (no-op) so Stripe's at-least-once retries are safe.

    Raises IdPForwardError on 5xx or network failure — let that bubble so
    Stripe's webhook retry loop can try again.
    """
    token = os.environ.get("CAVEID_SERVICE_TOKEN")
    if not token:
        # Log once loudly — we should never deploy with this env var missing.
        log.error("CAVEID_SERVICE_TOKEN is not set; cannot forward subscription update")
        raise IdPForwardError("service_token_missing")

    payload = {
        "user_id": user_id,
        "tier": tier,
        "stripe_subscription_id": stripe_subscription_id,
        "stripe_customer_id": stripe_customer_id,
        "stripe_event_id": stripe_event_id,
        "subscription_status": subscription_status,
        "subscription_plan": subscription_plan,
        "subscription_ends_at": subscription_ends_at,
    }
    # Strip None values — the IdP's endpoint treats absence as "don't update".
    payload = {k: v for k, v in payload.items() if v is not None}

    try:
        resp = httpx.post(
            _IDP_UPDATE_TIER_URL,
            json=payload,
            headers={"X-Service-Token": token},
            timeout=timeout_s,
        )
    except httpx.HTTPError as exc:
        raise IdPForwardError(f"idp_unreachable: {exc}") from exc

    if resp.status_code >= 500:
        raise IdPForwardError(f"idp_5xx: {resp.status_code} {resp.text[:200]}")
    if resp.status_code == 401:
        # Never retry auth failures — the token is wrong and retries won't fix it.
        log.error("IdP rejected service token — check CAVEID_SERVICE_TOKEN rotation")
        raise IdPForwardError("idp_auth_failed")
    if resp.status_code >= 400:
        # 4xx other than 401 = our payload was malformed; log + swallow so Stripe
        # doesn't hammer us forever.
        log.error("IdP rejected subscription update: %s %s", resp.status_code, resp.text[:200])
        return {"error": "idp_bad_request", "status": resp.status_code}

    return resp.json()
