from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from fusion_identity.deps import get_store, require_tenant_admin_of
from fusion_identity.models import (
    ApprovalValidateRequest,
    MenusAddRequest,
    RoleCreate,
    RoleMenusUpdate,
    RoleUpdate,
)
from fusion_identity.store import InMemoryStore, StoreConflict

logger = logging.getLogger(__name__)
_admin = require_tenant_admin_of("tenant_id")
router = APIRouter(prefix="/api/v1/tenants/{tenant_id}", tags=["rbac"])


@router.get("/roles")
async def list_roles(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> list[dict[str, Any]]:
    # Issue #12 (E5): built-in roles are fixed; per-tenant custom roles carry
    # write classes. Menus are the current matrix row for each role.
    return await store.list_roles(tenant_id)


@router.post("/roles", status_code=201)
async def create_role(
    tenant_id: str,
    body: RoleCreate,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(_admin),
) -> dict[str, Any]:
    try:
        rec = await store.create_custom_role(
            tenant_id, body.role_id, body.display_name, body.write_classes
        )
    except StoreConflict as exc:
        logger.warning("create_role: conflict role=%s tid=%s: %s", body.role_id, tenant_id, exc)
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await store.append_audit(
        tenant_id,
        claims.get("sub"),
        None,
        claims.get("role"),
        "rbac.role_create",
        "role",
        {"role_id": body.role_id, "write_classes": body.write_classes},
    )
    return rec


@router.patch("/roles/{role_id}")
async def update_role(
    tenant_id: str,
    role_id: str,
    body: RoleUpdate,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(_admin),
) -> dict[str, Any]:
    try:
        rec = await store.update_custom_role(
            tenant_id,
            role_id,
            display_name=body.display_name,
            write_classes=body.write_classes,
        )
    except StoreConflict as exc:
        # Built-in immutability surfaces as 403; everything else is 404/409.
        if "built-in and immutable" in str(exc):
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if rec is None:
        raise HTTPException(status_code=404, detail="role not found")
    await store.append_audit(
        tenant_id,
        claims.get("sub"),
        None,
        claims.get("role"),
        "rbac.role_update",
        "role",
        {"role_id": role_id},
    )
    return rec


@router.delete("/roles/{role_id}")
async def delete_role(
    tenant_id: str,
    role_id: str,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(_admin),
) -> dict[str, bool]:
    try:
        ok = await store.delete_custom_role(tenant_id, role_id)
    except StoreConflict as exc:
        if "built-in and immutable" in str(exc):
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        # Role still assigned to members — deletion would orphan the grant.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not ok:
        raise HTTPException(status_code=404, detail="role not found")
    await store.append_audit(
        tenant_id,
        claims.get("sub"),
        None,
        claims.get("role"),
        "rbac.role_delete",
        "role",
        {"role_id": role_id},
    )
    return {"deleted": True}


@router.get("/roles/{role_id}/menus")
async def get_role_menus(
    tenant_id: str,
    role_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    rec = await store.get_role(tenant_id, role_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="role not found")
    return {"role_id": role_id, "menus": rec["menus"], "built_in": rec["built_in"]}


@router.put("/roles/{role_id}/menus")
async def set_role_menus(
    tenant_id: str,
    role_id: str,
    body: RoleMenusUpdate,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(_admin),
) -> dict[str, Any]:
    # Issue #12 (E5): runtime-editable role <-> menu matrix. Takes effect on
    # the next verify call (next page load) — no frontend release needed.
    try:
        menus = await store.set_role_menus(tenant_id, role_id, body.menus)
    except StoreConflict as exc:
        logger.warning("set_role_menus: conflict role=%s tid=%s: %s", role_id, tenant_id, exc)
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await store.append_audit(
        tenant_id,
        claims.get("sub"),
        None,
        claims.get("role"),
        "rbac.menu_matrix_set",
        "role",
        {"role_id": role_id, "menus": menus},
    )
    return {"role_id": role_id, "menus": menus}


@router.post("/roles/{role_id}/menus/reset")
async def reset_role_menus(
    tenant_id: str,
    role_id: str,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(_admin),
) -> dict[str, Any]:
    try:
        menus = await store.reset_role_menus(tenant_id, role_id)
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await store.append_audit(
        tenant_id,
        claims.get("sub"),
        None,
        claims.get("role"),
        "rbac.menu_matrix_reset",
        "role",
        {"role_id": role_id},
    )
    return {"role_id": role_id, "menus": menus}


@router.get("/menus")
async def list_menus(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    return {"menus": await store.list_known_menus(tenant_id)}


@router.post("/menus", status_code=201)
async def add_menus(
    tenant_id: str,
    body: MenusAddRequest,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(_admin),
) -> dict[str, Any]:
    # Issue #12 (E5): menus are declared by module manifests; the admin
    # registers new menu ids here so the matrix editor can map them.
    try:
        menus = await store.add_known_menus(tenant_id, body.menus)
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await store.append_audit(
        tenant_id,
        claims.get("sub"),
        None,
        claims.get("role"),
        "rbac.menu_add",
        "menu",
        {"added": body.menus},
    )
    return {"menus": menus}


@router.post("/approvals/validate")
async def validate_approval(
    tenant_id: str,
    body: ApprovalValidateRequest,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(_admin),
) -> dict[str, Any]:
    # Issue #12 (E5): the requester != approver invariant is part of the
    # identity contract for any approval flow. Enforced server-side here so
    # gateway/shell approval gates share one authority.
    if body.requester_id == body.approver_id:
        logger.warning(
            "validate_approval: requester==approver tid=%s by=%s",
            tenant_id,
            claims.get("sub"),
        )
        raise HTTPException(status_code=403, detail="requester and approver must differ")
    for uid in (body.requester_id, body.approver_id):
        if await store.get_member(tenant_id, uid) is None:
            raise HTTPException(status_code=404, detail=f"member not found: {uid}")
    return {"valid": True}
