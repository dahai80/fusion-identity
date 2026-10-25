from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from fusion_identity.deps import get_store, require_permission_of
from fusion_identity.models import DepartmentCreate, DepartmentUpdate
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

# Issue #16: departments readable tenant-wide, write for member/operator,
# delete operator+admin via the matrix.
_read = require_permission_of("departments", "read")
_write = require_permission_of("departments", "write")
_delete = require_permission_of("departments", "delete")
router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/departments", tags=["departments"])


@router.post("", status_code=201)
async def create_department(
    tenant_id: str,
    body: DepartmentCreate,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(_write),
) -> dict[str, Any]:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    rec = await store.create_department(
        tenant_id,
        body.name,
        parent_id=body.parent_id,
        tool_allowlist=body.tool_allowlist,
    )
    logger.info(
        "create_department: dept=%s tenant=%s by=%s", rec["dept_id"], tenant_id, claims.get("sub")
    )
    return rec


@router.get("")
async def list_departments(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_read),
) -> list[dict[str, Any]]:
    return await store.list_departments(tenant_id)


@router.get("/{dept_id}")
async def get_department(
    tenant_id: str,
    dept_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_read),
) -> dict[str, Any]:
    rec = await store.get_department(tenant_id, dept_id)
    if not rec:
        raise HTTPException(status_code=404, detail="department not found")
    return rec


@router.patch("/{dept_id}")
async def update_department(
    tenant_id: str,
    dept_id: str,
    body: DepartmentUpdate,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_write),
) -> dict[str, Any]:
    rec = await store.update_department(
        tenant_id,
        dept_id,
        name=body.name,
        parent_id=body.parent_id,
        tool_allowlist=body.tool_allowlist,
    )
    if not rec:
        raise HTTPException(status_code=404, detail="department not found")
    return rec


@router.delete("/{dept_id}")
async def delete_department(
    tenant_id: str,
    dept_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_delete),
) -> dict[str, Any]:
    if not await store.delete_department(tenant_id, dept_id):
        raise HTTPException(status_code=404, detail="department not found")
    return {"deleted": True, "dept_id": dept_id}
