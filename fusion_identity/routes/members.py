from __future__ import annotations

import logging
import secrets
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

logger = logging.getLogger(__name__)
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
            # M6: generic message — do not echo store internals.
            logger.warning("add_or_create_member: create_user conflict user=%s", body.username)
            raise HTTPException(status_code=409, detail="username conflict") from exc
        uid = user_id
    else:
        # L21: an existing global user may be added to THIS tenant only by an
        # explicit, proof-bearing flow. A bare POST with just username+role
        # would let a tenant_admin silently claim any platform user. Require
        # the caller to assert ownership via the existing user's password, so
        # adding a pre-existing identity is never a silent member injection.
        raise HTTPException(
            status_code=409,
            detail=(
                "username already exists; to add an existing user to this tenant "
                "use the member-add-by-proof endpoint with the user's password"
            ),
        )
    member = await store.get_member(tenant_id, uid)
    if member is not None:
        raise HTTPException(status_code=409, detail="user already a member")
    try:
        return await store.add_member(tenant_id, uid, body.role, added_by=_claims.get("sub"))
    except StoreConflict as exc:
        logger.warning("add_or_create_member: add_member conflict user=%s", uid)
        raise HTTPException(status_code=400, detail="invalid member request") from exc


@router.post("/by-proof", status_code=201)
async def add_existing_member_by_proof(
    tenant_id: str,
    body: MemberCreate,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    """L21: add a pre-existing platform user to this tenant, proving ownership
    with the user's current password. Without proof a tenant_admin could
    silently claim any global username as a member."""
    from fusion_identity.store import verify_password

    existing = await store.get_user_by_username(body.username)
    if existing is None:
        raise HTTPException(status_code=404, detail="user not found")
    uid = existing["user_id"]
    ok, _needs = verify_password(
        body.password,
        password_hash_v=existing.get("password_hash_v", ""),
        password_hash=existing.get("password_hash", ""),
        salt=existing.get("salt", "fusion-identity"),
        algo=existing.get("password_algo", "scrypt"),
    )
    if not ok:
        logger.warning("add_existing_member_by_proof: bad password user=%s", uid)
        raise HTTPException(status_code=401, detail="ownership proof failed")
    member = await store.get_member(tenant_id, uid)
    if member is not None:
        raise HTTPException(status_code=409, detail="user already a member")
    try:
        return await store.add_member(tenant_id, uid, body.role, added_by=_claims.get("sub"))
    except StoreConflict as exc:
        logger.warning("add_existing_member_by_proof: add_member conflict user=%s", uid)
        raise HTTPException(status_code=400, detail="invalid member request") from exc


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
        logger.warning("update_member_role: conflict user=%s", user_id)
        raise HTTPException(status_code=400, detail="invalid role request") from exc
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
    # L20: this route mutates the global user.status (platform identity). It
    # MUST be gated on the user being a member of THIS tenant, otherwise a
    # tenant_admin of A could disable a user that only belongs to B. The
    # member record is the tenant-scoped authorization boundary here.
    member = await store.get_member(tenant_id, user_id)
    if member is None:
        raise HTTPException(status_code=404, detail="member not found")
    if body.status == "disabled":
        count = await store.count_members_by_role(tenant_id, "tenant_admin")
        if member["role"] == "tenant_admin" and count <= 1:
            raise HTTPException(status_code=403, detail="cannot disable last tenant_admin")
    u = await store.update_user(user_id, status=body.status)
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    logger.warning(
        "update_member_status: tenant=%s user=%s status=%s by=%s",
        tenant_id,
        user_id,
        body.status,
        _claims.get("sub"),
    )
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
    # L20: password reset is a credential reset on the platform identity, but
    # it must only be actionable by an admin of a tenant the user belongs to.
    from fusion_identity.store import hash_password

    member = await store.get_member(tenant_id, user_id)
    if member is None:
        raise HTTPException(status_code=404, detail="member not found")
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
    logger.warning(
        "reset_member_password: tenant=%s user=%s by=%s", tenant_id, user_id, _claims.get("sub")
    )
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
