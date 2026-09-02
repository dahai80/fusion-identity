from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from fusion_identity.deps import get_store, require_tenant_admin_of
from fusion_identity.models import (
    MemberCreate,
    MemberRoleUpdate,
    MemberStatusUpdate,
    PasswordResetRequest,
)
from fusion_identity.store import InMemoryStore, StoreConflict

_admin = require_tenant_admin_of("tenant_id")
router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/members", tags=["members"])


@router.get("")
async def list_members(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> list[dict[str, Any]]:
    return await store.list_members(tenant_id)


@router.post("", status_code=201)
async def add_or_create_member(
    tenant_id: str,
    body: MemberCreate,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    existing = await store.get_user_by_username(body.username)
    if existing is None:
        import secrets

        user_id = "usr_" + secrets.token_hex(6)
        try:
            await store.create_user(
                user_id,
                body.username,
                body.password,
                body.email,
                must_change_password=True,
            )
        except StoreConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        uid = user_id
    else:
        uid = existing["user_id"]
    member = await store.get_member(tenant_id, uid)
    if member is not None:
        raise HTTPException(status_code=409, detail="user already a member")
    try:
        return await store.add_member(tenant_id, uid, body.role, added_by=_claims.get("sub"))
    except StoreConflict as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/{user_id}")
async def update_member_role(
    tenant_id: str,
    user_id: str,
    body: MemberRoleUpdate,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    if user_id == _claims.get("sub"):
        raise HTTPException(status_code=403, detail="cannot change own role")
    if body.role != "tenant_admin":
        count = await store.count_members_by_role(tenant_id, "tenant_admin")
        member = await store.get_member(tenant_id, user_id)
        if member and member["role"] == "tenant_admin" and count <= 1:
            raise HTTPException(status_code=403, detail="cannot demote last tenant_admin")
    try:
        m = await store.update_member_role(tenant_id, user_id, body.role)
    except StoreConflict as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not m:
        raise HTTPException(status_code=404, detail="member not found")
    await store.append_audit(
        tenant_id,
        _claims.get("sub"),
        None,
        _claims.get("role"),
        "member.role_change",
        "member",
        {"user_id": user_id, "role": body.role},
    )
    return m


@router.patch("/{user_id}/status")
async def update_member_status(
    tenant_id: str,
    user_id: str,
    body: MemberStatusUpdate,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    if body.status == "disabled":
        count = await store.count_members_by_role(tenant_id, "tenant_admin")
        member = await store.get_member(tenant_id, user_id)
        if member and member["role"] == "tenant_admin" and count <= 1:
            raise HTTPException(status_code=403, detail="cannot disable last tenant_admin")
    u = await store.update_user(user_id, status=body.status)
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    await store.append_audit(
        tenant_id,
        _claims.get("sub"),
        None,
        _claims.get("role"),
        "member.status_change",
        "member",
        {"user_id": user_id, "status": body.status},
    )
    return {"user_id": user_id, "status": body.status}


@router.post("/{user_id}/password")
async def reset_member_password(
    tenant_id: str,
    user_id: str,
    body: PasswordResetRequest,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, bool]:
    from fusion_identity.store import hash_password

    pw_hash, salt, algo = hash_password(body.new_password)
    u = await store.update_user(
        user_id,
        password_hash_v=pw_hash,
        salt=salt,
        password_algo=algo,
        must_change_password=True,
    )
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    await store.append_audit(
        tenant_id,
        _claims.get("sub"),
        None,
        _claims.get("role"),
        "member.password_reset",
        "member",
        {"user_id": user_id},
    )
    return {"reset": True}


@router.delete("/{user_id}")
async def remove_member(
    tenant_id: str,
    user_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, bool]:
    if user_id == _claims.get("sub"):
        raise HTTPException(status_code=403, detail="cannot remove self")
    count = await store.count_members_by_role(tenant_id, "tenant_admin")
    member = await store.get_member(tenant_id, user_id)
    if member and member["role"] == "tenant_admin" and count <= 1:
        raise HTTPException(status_code=403, detail="cannot remove last tenant_admin")
    ok = await store.remove_member(tenant_id, user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="member not found")
    await store.append_audit(
        tenant_id,
        _claims.get("sub"),
        None,
        _claims.get("role"),
        "member.remove",
        "member",
        {"user_id": user_id},
    )
    return {"removed": True}
