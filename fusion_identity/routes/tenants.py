from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity.deps import get_store, invalidate_tenant_cache, require_permission_of
from fusion_identity.events import EVENT_TENANT_STATUS_CHANGED, emit_event
from fusion_identity.models import TenantUpdate
from fusion_identity.store import InMemoryStore, StoreConflict

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])

# Issue #16: explicit permission points — tenant info is readable by every
# built-in role, mutation (status change) stays tenant_admin-only via the
# matrix (no non-admin row for "tenants": "write").
_read = require_permission_of("tenants", "read")
_write = require_permission_of("tenants", "write")


@router.get("")
async def list_tenants_self(
    _claims: dict = Depends(_read),
    store: InMemoryStore = Depends(get_store),
) -> list[dict[str, Any]]:
    tid = _claims["tid"]
    return await store.list_tenants_for(tid)


@router.get("/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_read),
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
    _claims: dict = Depends(_write),
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
        await emit_event(
            store,
            EVENT_TENANT_STATUS_CHANGED,
            tenant_id,
            {"tenant_id": tenant_id, "status": fields["status"]},
        )
    await invalidate_tenant_cache(request, tenant_id)
    return t
