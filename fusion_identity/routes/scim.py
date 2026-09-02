from __future__ import annotations

import logging
import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from fusion_identity.deps import require_service_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scim/v2", tags=["scim"])


@router.get("/Users")
async def list_users(
    request: Request,
    tenant_id: str = Query(..., alias="tenantId"),
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    store = request.app.state.store
    members = await store.list_members(tenant_id)
    resources = []
    for m in members:
        user = await store.get_user(m["user_id"])
        if user is None:
            continue
        resources.append(
            {
                "id": user["user_id"],
                "userName": user["username"],
                "displayName": user.get("display_name") or user["username"],
                "active": user.get("status", "active") == "active",
                "tenant_id": tenant_id,
            }
        )
    logger.info("scim list_users: tenant=%s count=%d", tenant_id, len(resources))
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(resources),
        "Resources": resources,
    }


@router.post("/Users")
async def create_user(
    request: Request,
    body: dict[str, Any],
    tenant_id: str = Query(..., alias="tenantId"),
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    store = request.app.state.store
    tenant = await store.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    username = body.get("userName")
    if not username:
        raise HTTPException(status_code=400, detail="userName required")
    existing = await store.get_user_by_username(username)
    if existing is not None:
        raise HTTPException(status_code=409, detail="user already exists")
    uid = "usr_" + secrets.token_hex(6)
    display = body.get("displayName") or username
    active = body.get("active", True)
    await store.create_user(uid, username, secrets.token_hex(16), must_change_password=False)
    if display:
        await store.update_user(uid, display_name=display)
    if not active:
        await store.update_user(uid, status="disabled")
    await store.add_member(tenant_id, uid, "member")
    logger.warning("scim create_user: tenant=%s user=%s", tenant_id, uid)
    await store.append_audit(
        tenant_id, uid, None, None, "scim.user.create", "user", {"userName": username}
    )
    return {
        "id": uid,
        "userName": username,
        "displayName": display,
        "active": active,
        "tenant_id": tenant_id,
    }


def _scim_user_view(user: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    return {
        "id": user["user_id"],
        "userName": user["username"],
        "displayName": user.get("display_name") or user["username"],
        "active": user.get("status", "active") == "active",
        "tenant_id": tenant_id,
    }


@router.get("/Users/{user_id}")
async def get_user(
    request: Request,
    user_id: str,
    tenant_id: str = Query(..., alias="tenantId"),
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    store = request.app.state.store
    member = await store.get_member(tenant_id, user_id)
    if member is None:
        raise HTTPException(status_code=404, detail="user not found in tenant")
    user = await store.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    logger.info("scim get_user: tenant=%s user=%s", tenant_id, user_id)
    return _scim_user_view(user, tenant_id)


@router.patch("/Users/{user_id}")
async def patch_user(
    request: Request,
    user_id: str,
    body: dict[str, Any],
    tenant_id: str = Query(..., alias="tenantId"),
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    store = request.app.state.store
    member = await store.get_member(tenant_id, user_id)
    if member is None:
        raise HTTPException(status_code=404, detail="user not found in tenant")
    user = await store.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    fields: dict[str, Any] = {}
    if "displayName" in body and body["displayName"] is not None:
        fields["display_name"] = body["displayName"]
    if "userName" in body and body["userName"] is not None:
        fields["display_name"] = body["userName"]
    if "active" in body:
        fields["status"] = "active" if body["active"] else "disabled"
    if fields:
        user = await store.update_user(user_id, **fields)
    logger.warning("scim patch_user: tenant=%s user=%s fields=%s", tenant_id, user_id, list(fields))
    await store.append_audit(
        tenant_id, user_id, None, None, "scim.user.patch", "user", {"fields": list(fields)}
    )
    return _scim_user_view(user or {}, tenant_id)


@router.delete("/Users/{user_id}")
async def delete_user(
    request: Request,
    user_id: str,
    tenant_id: str = Query(..., alias="tenantId"),
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    store = request.app.state.store
    member = await store.get_member(tenant_id, user_id)
    if member is None:
        raise HTTPException(status_code=404, detail="user not found in tenant")
    await store.remove_member(tenant_id, user_id)
    await store.update_user(user_id, status="disabled")
    logger.warning("scim delete_user: tenant=%s user=%s", tenant_id, user_id)
    await store.append_audit(
        tenant_id, user_id, None, None, "scim.user.delete", "user", {"user_id": user_id}
    )
    return {"deleted": True, "id": user_id}
