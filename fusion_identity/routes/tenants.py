from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity.deps import get_store, invalidate_tenant_cache, require_tenant_admin_of
from fusion_identity.models import TenantUpdate
from fusion_identity.store import InMemoryStore, StoreConflict

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])

_self = require_tenant_admin_of("tenant_id")


@router.get("")
async def list_tenants_self(
    _claims: dict = Depends(_self),
    store: InMemoryStore = Depends(get_store),
) -> list[dict[str, Any]]:
    tid = _claims["tid"]
    return await store.list_tenants_for(tid)


@router.get("/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_self),
) -> dict[str, Any]:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    return t


@router.patch("/{tenant_id}")
async def update_tenant(
    tenant_id: str,
    body: TenantUpdate,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_self),
) -> dict[str, Any]:
    fields = body.model_dump(exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="no fields to update")
    try:
        t = await store.update_tenant(tenant_id, **fields)
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    if "status" in fields:
        await store.append_audit(
            tenant_id,
            _claims.get("sub"),
            None,
            _claims.get("role"),
            "tenant.status_change",
            "tenant",
            {"status": fields["status"]},
        )
    await invalidate_tenant_cache(request, tenant_id)
    return t
