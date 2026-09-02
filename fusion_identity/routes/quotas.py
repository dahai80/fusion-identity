from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from fusion_identity.deps import get_store, require_tenant_admin_of
from fusion_identity.models import QuotaUpdate
from fusion_identity.store import InMemoryStore

_admin = require_tenant_admin_of("tenant_id")
router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/quotas", tags=["quotas"])


@router.get("")
async def get_quota(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    q = await store.get_quota(tenant_id)
    if not q:
        raise HTTPException(status_code=404, detail="tenant not found")
    return q


@router.put("")
async def put_quota(
    tenant_id: str,
    body: QuotaUpdate,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    fields = body.model_dump(exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="no fields to update")
    q = await store.put_quota(tenant_id, **fields)
    if not q:
        raise HTTPException(status_code=404, detail="tenant not found")
    return q
