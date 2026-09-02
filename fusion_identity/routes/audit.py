from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from fusion_identity.deps import get_store, require_tenant_admin_of
from fusion_identity.store import InMemoryStore

_admin = require_tenant_admin_of("tenant_id")
router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/audit", tags=["audit"])


@router.get("")
async def list_audit(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
    limit: int = 100,
    since: float | None = None,
    until: float | None = None,
    cursor: int | None = None,
) -> list[dict[str, Any]]:
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be 1..1000")
    return await store.list_audit(
        tenant_id,
        limit=limit,
        since=since,
        until=until,
        cursor=cursor,
    )


@router.get("/verify")
async def verify_audit(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    return await store.verify_audit_chain(tenant_id)
