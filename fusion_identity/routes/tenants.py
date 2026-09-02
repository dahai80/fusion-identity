from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from fusion_identity.deps import get_store, require_tenant_admin
from fusion_identity.models import TenantCreate, TenantUpdate
from fusion_identity.store import InMemoryStore, StoreConflict

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])


@router.get("")
async def list_tenants(
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(require_tenant_admin),
) -> list[dict[str, Any]]:
    return await store.list_tenants()


@router.post("", status_code=201)
async def create_tenant(
    body: TenantCreate,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(require_tenant_admin),
) -> dict[str, Any]:
    try:
        return await store.create_tenant(body.tenant_id, body.display_name, body.plan)
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(require_tenant_admin),
) -> dict[str, Any]:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    return t


@router.patch("/{tenant_id}")
async def update_tenant(
    tenant_id: str,
    body: TenantUpdate,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(require_tenant_admin),
) -> dict[str, Any]:
    fields = body.model_dump(exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="no fields to update")
    t = await store.update_tenant(tenant_id, **fields)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    return t


@router.delete("/{tenant_id}")
async def delete_tenant(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(require_tenant_admin),
) -> dict[str, bool]:
    ok = await store.delete_tenant(tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail="tenant not found")
    return {"deleted": True}
