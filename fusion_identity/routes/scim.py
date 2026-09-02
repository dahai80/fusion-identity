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
    start_index: int = Query(default=1, alias="startIndex", ge=1),
    count: int = Query(default=100, alias="count", ge=1, le=1000),
    filter_: str | None = Query(default=None, alias="filter"),
    sort_by: str | None = Query(default=None, alias="sortBy"),
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
    resources = _apply_scim_filter(resources, filter_)
    if sort_by:
        resources.sort(key=lambda r: str(r.get(sort_by, "")))
    total = len(resources)
    page = resources[start_index - 1 : start_index - 1 + count]
    logger.info(
        "scim list_users: tenant=%s total=%d page=%d filter=%s sortBy=%s",
        tenant_id,
        total,
        len(page),
        filter_,
        sort_by,
    )
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(page),
        "Resources": page,
    }


def _apply_scim_filter(
    resources: list[dict[str, Any]], filter_expr: str | None
) -> list[dict[str, Any]]:
    if not filter_expr:
        return resources
    import re

    m = re.match(r'(\w+)\s+eq\s+"?([^"]+)"?', filter_expr.strip())
    if not m:
        logger.warning("scim filter unsupported: %s", filter_expr)
        return resources
    attr, val = m.group(1), m.group(2)
    return [r for r in resources if str(r.get(attr, "")) == val]


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


_SCIM_GROUP_ROLES = ["tenant_admin", "operator", "member", "viewer"]


@router.get("/Groups")
async def list_groups(
    request: Request,
    tenant_id: str = Query(..., alias="tenantId"),
    start_index: int = Query(default=1, alias="startIndex", ge=1),
    count: int = Query(default=100, alias="count", ge=1, le=1000),
    filter_: str | None = Query(default=None, alias="filter"),
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    store = request.app.state.store
    members = await store.list_members(tenant_id)
    by_role: dict[str, list[str]] = {r: [] for r in _SCIM_GROUP_ROLES}
    for m in members:
        role = m.get("role", "member")
        if role in by_role:
            by_role[role].append(m["user_id"])
    resources = [
        {
            "id": f"{tenant_id}:{role}",
            "displayName": f"{tenant_id} {role}",
            "members": [{"value": uid, "$ref": f"/scim/v2/Users/{uid}"} for uid in uids],
        }
        for role, uids in by_role.items()
        if uids
    ]
    if filter_:
        import re

        m = re.match(r'(\w+)\s+eq\s+"?([^"]+)"?', filter_.strip())
        if m:
            attr, val = m.group(1), m.group(2)
            resources = [r for r in resources if str(r.get(attr, "")) == val]
        else:
            logger.warning("scim groups filter unsupported: %s", filter_)
    total = len(resources)
    page = resources[start_index - 1 : start_index - 1 + count]
    logger.info("scim list_groups: tenant=%s total=%d", tenant_id, total)
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(page),
        "Resources": page,
    }


@router.get("/Groups/{group_id}")
async def get_group(
    request: Request,
    group_id: str,
    tenant_id: str = Query(..., alias="tenantId"),
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    store = request.app.state.store
    members = await store.list_members(tenant_id)
    role = group_id.split(":")[-1] if ":" in group_id else group_id
    uids = [m["user_id"] for m in members if m.get("role") == role]
    logger.info("scim get_group: tenant=%s group=%s members=%d", tenant_id, group_id, len(uids))
    return {
        "id": group_id,
        "displayName": f"{tenant_id} {role}",
        "members": [{"value": uid, "$ref": f"/scim/v2/Users/{uid}"} for uid in uids],
    }
