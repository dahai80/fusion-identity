from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from fusion_identity.deps import get_store, require_tenant_admin_of
from fusion_identity.models import MemberCreate
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
            await store.create_user(user_id, body.username, body.password, body.email)
        except StoreConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        uid = user_id
    else:
        uid = existing["user_id"]
    member = await store.get_member(tenant_id, uid)
    if member is not None:
        raise HTTPException(status_code=409, detail="user already a member")
    try:
        return await store.add_member(tenant_id, uid, body.role)
    except StoreConflict as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{user_id}")
async def remove_member(
    tenant_id: str,
    user_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, bool]:
    ok = await store.remove_member(tenant_id, user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="member not found")
    return {"removed": True}
