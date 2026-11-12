from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from fusion_identity.deps import get_settings, get_store, require_service_token
from fusion_identity.payments import PaymentError, compute_promo, get_provider
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["recharge"],
    dependencies=[Depends(require_service_token)],
)


class RechargeOrderCreate(BaseModel):
    tokens: int = Field(gt=0, le=1_000_000_000)


async def _require_tenant(store, tenant_id: str) -> dict:
    tenant = await store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="tenant not found")
    return tenant


@router.post("/tenants/{tenant_id}/recharge/orders")
async def create_recharge_order(
    tenant_id: str,
    body: RechargeOrderCreate,
    store: InMemoryStore = Depends(get_store),
    settings=Depends(get_settings),
):
    await _require_tenant(store, tenant_id)
    try:
        provider = get_provider(settings.payment_provider)
    except PaymentError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    first_paid = await store.count_paid_prepaid_orders(tenant_id) == 0
    promo = compute_promo(body.tokens, settings.first_purchase_promo_pct, first_paid)
    order = await store.create_prepaid_order(tenant_id, body.tokens, promo, provider.name)
    logger.info(
        "recharge order created: tenant=%s order=%s tokens=%d promo=%d provider=%s",
        tenant_id,
        order["order_id"],
        body.tokens,
        promo,
        provider.name,
    )
    return order


@router.get("/tenants/{tenant_id}/recharge/orders")
async def list_recharge_orders(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
):
    await _require_tenant(store, tenant_id)
    return await store.list_prepaid_orders(tenant_id)


@router.get("/tenants/{tenant_id}/recharge/orders/{order_id}")
async def get_recharge_order(
    tenant_id: str,
    order_id: str,
    store: InMemoryStore = Depends(get_store),
):
    await _require_tenant(store, tenant_id)
    order = await store.get_prepaid_order(order_id)
    if not order or order["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="order not found")
    return order


@router.post("/tenants/{tenant_id}/recharge/orders/{order_id}/pay")
async def pay_recharge_order(
    tenant_id: str,
    order_id: str,
    store: InMemoryStore = Depends(get_store),
    settings=Depends(get_settings),
):
    await _require_tenant(store, tenant_id)
    order = await store.get_prepaid_order(order_id)
    if not order or order["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="order not found")
    try:
        provider = get_provider(settings.payment_provider)
    except PaymentError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if order["status"] == "paid":
        # Idempotent replay: the ledger credit happened on the first
        # transition only — return the paid record unchanged.
        logger.info("recharge pay replay: order=%s already paid", order_id)
        return order
    if order["status"] != "created":
        raise HTTPException(status_code=409, detail=f"order is {order['status']}")
    result = await provider.charge(tenant_id, order_id, order["tokens"])
    paid = await store.mark_prepaid_order_paid(order_id, result.provider_ref)
    if not paid:
        raise HTTPException(status_code=409, detail="order transition failed")
    await store.append_audit(
        tenant_id,
        None,
        None,
        "service",
        "recharge.paid",
        order_id,
        {
            "tokens": paid["tokens"],
            "promo_tokens": paid["promo_tokens"],
            "provider": paid["provider"],
            "provider_ref": paid["provider_ref"],
        },
    )
    logger.info(
        "recharge paid: tenant=%s order=%s credited=%d",
        tenant_id,
        order_id,
        paid["tokens"] + paid["promo_tokens"],
    )
    return paid


@router.get("/tenants/{tenant_id}/recharge/balance")
async def get_recharge_balance(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
):
    await _require_tenant(store, tenant_id)
    balance = await store.get_balance(tenant_id)
    return {"tenant_id": tenant_id, "balance": balance}
