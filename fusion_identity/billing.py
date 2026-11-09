from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx
from fusion_core.http_client import get_async_client

logger = logging.getLogger(__name__)

# Issue #60: pluggable sync billing hook for the fusion-commerce wallet.
# Called on the LLM lease path (AuthorizeAndAcquire) right before the lease
# is granted. Disabled entirely when FUSION_IDENTITY_BILLING_URL is empty —
# zero behavior change by default.
#
# Contract (fusion-commerce arch doc §5.2 / §14, owner decision: deduct per
# call): POST <url> with X-Fusion-Tenant + internal bearer token, body
# {"amount": <tokens>, "ref_id": <lease_id>}. 200 {granted:true,...} ->
# proceed; 402 {"error":"quota_exhausted"} -> refuse with the existing
# quota-exhausted semantics (run parks, resumes after top-up).
#
# Failure semantics: commerce unreachable / unexpected status follows
# FUSION_IDENTITY_BILLING_FAIL_MODE ("open" default, "closed" to refuse) —
# a commerce outage must not take down all generation by default.

_BILLING_TIMEOUT_S = 2.0
_BILLING_HIGH_LATENCY_MS = 200.0


class BillingRefused(Exception):
    """Billing declined the lease — map to the quota-exhausted refuse path."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def billing_config() -> dict[str, str]:
    return {
        "url": (os.environ.get("FUSION_IDENTITY_BILLING_URL") or "").strip(),
        "token": (os.environ.get("FUSION_IDENTITY_BILLING_TOKEN") or "").strip(),
        "fail_mode": (os.environ.get("FUSION_IDENTITY_BILLING_FAIL_MODE") or "open")
        .strip()
        .lower(),
    }


def _fail_open(mode: str, detail: str, tenant_id: str, lease_id: str) -> None:
    if mode == "closed":
        raise BillingRefused(f"billing fail-closed: {detail}")
    logger.error("billing hook fail-open: %s (tenant=%s lease=%s)", detail, tenant_id, lease_id)


async def consume_wallet(
    tenant_id: str,
    lease_id: str,
    target_module: str,
    amount: int,
) -> None:
    """Deduct one call's token reservation from the tenant wallet.

    Raises BillingRefused when the wallet declines (402) or fail-mode is
    closed and commerce is unreachable. Never raises when disabled.
    """
    cfg = billing_config()
    if not cfg["url"]:
        return
    headers = {"X-Fusion-Tenant": tenant_id}
    if cfg["token"]:
        headers["Authorization"] = f"Bearer {cfg['token']}"
    payload = {
        "amount": int(amount),
        "ref_id": lease_id,
        "module": target_module,
    }
    start = time.perf_counter()
    try:
        client = get_async_client(cfg["url"], timeout=_BILLING_TIMEOUT_S)
        resp: httpx.Response = await client.post(
            "/api/wallet/consume", json=payload, headers=headers
        )
    except Exception as exc:
        _fail_open(cfg["fail_mode"], f"billing unreachable: {exc}", tenant_id, lease_id)
        return
    cost_ms = (time.perf_counter() - start) * 1000
    if cost_ms > _BILLING_HIGH_LATENCY_MS:
        logger.warning(
            "billing hook high latency: %.1fms (tenant=%s lease=%s)",
            cost_ms,
            tenant_id,
            lease_id,
        )
    if resp.status_code == 200:
        try:
            data: dict[str, Any] = resp.json()
        except Exception:
            data = {}
        if data.get("granted") is False:
            _fail_open(cfg["fail_mode"], "billing granted=false", tenant_id, lease_id)
        return
    if resp.status_code == 402:
        logger.info("billing refused: wallet exhausted (tenant=%s lease=%s)", tenant_id, lease_id)
        raise BillingRefused("billing: wallet quota exhausted (top up to resume)")
    _fail_open(
        cfg["fail_mode"],
        f"billing unexpected status {resp.status_code}",
        tenant_id,
        lease_id,
    )
