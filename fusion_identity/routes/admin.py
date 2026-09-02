from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from fusion_identity.deps import (
    get_cache,
    get_store,
    invalidate_tenant_cache,
    require_service_token,
)
from fusion_identity.store import InMemoryStore, StoreConflict

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["admin"],
    dependencies=[Depends(require_service_token)],
)


class AdminTenantCreate(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    plan: str = Field(default="standard", max_length=32)
    tier: str | None = Field(default=None, max_length=32)
    max_concurrency: int | None = Field(default=None, ge=0)
    daily_token_limit: int | None = Field(default=None, ge=0)
    allowed_modules: list[str] | None = None
    allowed_models: list[str] | None = None


class AdminTenantUpdate(BaseModel):
    max_concurrency: int | None = Field(default=None, ge=0)
    daily_token_limit: int | None = Field(default=None, ge=0)
    allowed_modules: list[str] | None = None
    allowed_models: list[str] | None = None
    display_name: str | None = Field(default=None, max_length=128)
    status: str | None = Field(default=None, max_length=16)


class AdminApiKeyCreate(BaseModel):
    user_id: str | None = None
    name: str | None = None
    scopes: list[str] = Field(default_factory=list)
    expires_in_days: int | None = Field(default=None, ge=1)


def _quota_fields(body: AdminTenantCreate | AdminTenantUpdate) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if getattr(body, "max_concurrency", None) is not None:
        fields["concurrent"] = body.max_concurrency
    if getattr(body, "daily_token_limit", None) is not None:
        fields["tpm"] = body.daily_token_limit
    if getattr(body, "allowed_modules", None) is not None:
        fields["allowed_modules"] = body.allowed_modules
    if getattr(body, "allowed_models", None) is not None:
        fields["allowed_models"] = body.allowed_models
    return fields


@router.get("/tenants")
async def admin_list_tenants(
    store: InMemoryStore = Depends(get_store),
) -> list[dict[str, Any]]:
    return await store.list_tenants()


@router.post("/tenants", status_code=201)
async def admin_create_tenant(
    body: AdminTenantCreate,
    request: Request,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    try:
        t = await store.create_tenant(
            body.tenant_id, display_name=body.display_name, plan=body.plan
        )
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    quota_fields = _quota_fields(body)
    if quota_fields:
        await store.put_quota(body.tenant_id, **quota_fields)
    await invalidate_tenant_cache(request, body.tenant_id)
    logger.info("admin_create_tenant: %s plan=%s", body.tenant_id, body.plan)
    return t


@router.put("/tenants/{tenant_id}")
async def admin_update_tenant(
    tenant_id: str,
    body: AdminTenantUpdate,
    request: Request,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    tenant_fields: dict[str, Any] = {}
    if body.display_name is not None:
        tenant_fields["display_name"] = body.display_name
    if body.status is not None:
        tenant_fields["status"] = body.status
    if tenant_fields:
        updated = await store.update_tenant(tenant_id, **tenant_fields)
        if updated is not None:
            t = updated
    quota_fields = _quota_fields(body)
    if quota_fields:
        await store.put_quota(tenant_id, **quota_fields)
    await invalidate_tenant_cache(request, tenant_id)
    logger.info("admin_update_tenant: %s", tenant_id)
    return t


@router.get("/tenants/{tenant_id}/quota")
async def admin_get_tenant_quota(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    q = await store.get_quota(tenant_id) or {}
    return {"tenant_id": tenant_id, "quota": q}


@router.post("/tenants/{tenant_id}/api-keys", status_code=201)
async def admin_create_api_key(
    tenant_id: str,
    body: AdminApiKeyCreate,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    raw, record = await store.create_api_key(tenant_id, body.user_id, scopes=body.scopes)
    logger.info("admin_create_api_key: tenant=%s user=%s", tenant_id, body.user_id)
    safe = {k: v for k, v in record.items() if k != "key_hash"}
    safe["raw_key"] = raw
    return safe


@router.post("/tenants/{tenant_id}/keys", status_code=201)
async def admin_create_api_key_alias(
    tenant_id: str,
    body: AdminApiKeyCreate,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    return await admin_create_api_key(tenant_id, body, store)


async def _revoke_tenant_api_key(
    request: Request, store: InMemoryStore, tenant_id: str, key_id: str
) -> None:
    keys = await store.list_api_keys(tenant_id)
    match = next((k for k in keys if k["key_id"] == key_id), None)
    if match is None:
        raise HTTPException(status_code=404, detail="api key not found in tenant")
    ok = await store.revoke_api_key(key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="api key already revoked")
    cache = get_cache(request)
    if cache is not None and match.get("key_hash"):
        # P2-11: fail-closed — match the api_keys route behavior. A swallowed
        # cache-invalidate failure leaves the revoked key live for up to TTL.
        try:
            await cache.invalidate_api_key_by_hash(match["key_hash"])
        except Exception as exc:
            logger.error("admin_revoke_api_key: cache invalidate failed (fail-closed): %s", exc)
            raise HTTPException(
                status_code=500,
                detail=(
                    "api key revoked but cache invalidation failed — key may remain valid up to TTL"
                ),
            ) from exc
    logger.warning("admin_revoke_api_key: tenant=%s key=%s", tenant_id, key_id)


@router.delete("/tenants/{tenant_id}/api-keys/{key_id}")
async def admin_revoke_api_key(
    tenant_id: str,
    key_id: str,
    request: Request,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    await _revoke_tenant_api_key(request, store, tenant_id, key_id)
    return {"revoked": True, "key_id": key_id}


@router.delete("/tenants/{tenant_id}/keys/{key_id}")
async def admin_revoke_api_key_alias(
    tenant_id: str,
    key_id: str,
    request: Request,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    await _revoke_tenant_api_key(request, store, tenant_id, key_id)
    return {"revoked": True, "key_id": key_id}


@router.get("/tenants/{tenant_id}/usage/today")
async def admin_usage_today(
    tenant_id: str,
    request: Request,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    day_start = time.time() - 86400
    agg = await store.aggregate_usage(tenant_id, since=day_start)
    by_metric = {r["metric"]: int(r.get("value", 0)) for r in agg}
    prompt = by_metric.get("prompt_tokens", 0)
    completion = by_metric.get("completion_tokens", 0)
    total_tokens = by_metric.get("tokens", 0)
    token_total = total_tokens + prompt + completion
    quota = await store.get_quota(tenant_id) or {}
    daily_limit = int(quota.get("tpm", 50000)) if quota.get("tpm") is not None else 50000
    usage_pct = round(token_total / daily_limit * 100, 2) if daily_limit > 0 else 0.0
    max_limit = int(quota.get("concurrent", 0)) if quota.get("concurrent") is not None else 0
    current_active = 0
    concurrency = request.app.state.concurrency
    if concurrency is not None:
        try:
            current_active = await concurrency.active_count(tenant_id)
        except Exception as exc:
            logger.warning("admin_usage_today: concurrency count failed: %s", exc)
    logger.info(
        "admin_usage_today: tenant=%s tokens=%d active=%d/%d",
        tenant_id,
        token_total,
        current_active,
        max_limit,
    )
    return {
        "tenant_id": tenant_id,
        "window": "24h",
        "concurrency": {"current_active": current_active, "max_limit": max_limit},
        "tokens": {
            "prompt_tokens_today": prompt,
            "completion_tokens_today": completion,
            "total_today": token_total,
            "daily_limit": daily_limit,
            "usage_percentage": usage_pct,
        },
    }
