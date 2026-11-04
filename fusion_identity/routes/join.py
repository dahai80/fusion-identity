from __future__ import annotations

import hashlib
import logging
import secrets
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from fusion_identity.deps import (
    get_store,
    require_bearer,
    require_tenant_admin_of,
)
from fusion_identity.ratelimit import check_login_rate
from fusion_identity.store import InMemoryStore, StoreConflict

logger = logging.getLogger(__name__)

# Issue #40 (fusion-site-auth-1104 §4): the join-policy plane. `proof`
# already exists as POST /members/by-proof; everything else lives here:
#   invite   — tenant_admin mints a single-use expiring token with a
#              pre-assigned role; the bearer redeems it
#   approval — user submits a join request; tenant_admin approves/rejects
#   open     — user self-adds, role forced to member
# All mutations are rate-limited and audited to the target tenant.
router = APIRouter(tags=["join"])

INVITE_PREFIX = "finv_"
DEFAULT_INVITE_TTL_SECONDS = 7 * 86400


class InviteCreate(BaseModel):
    role: str = Field(default="member", max_length=64)
    email: str | None = Field(default=None, max_length=254)
    ttl_seconds: int = Field(default=DEFAULT_INVITE_TTL_SECONDS, ge=60, le=30 * 86400)


class InviteRedeemRequest(BaseModel):
    token: str = Field(min_length=16, max_length=256)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _invite_expired(expires_at: Any) -> bool:
    # InMemory stores the epoch float; PgStore returns a TIMESTAMPTZ datetime.
    if isinstance(expires_at, (int, float)):
        return expires_at < time.time()
    import datetime

    return expires_at < datetime.datetime.now(datetime.UTC)


async def _audit(
    store: InMemoryStore, tenant_id: str, action: str, user_id: str | None, detail: dict
) -> None:
    try:
        await store.append_audit(
            tenant_id,
            user_id,
            None,
            None,
            action,
            None,
            detail,
        )
    except Exception:
        logger.exception("join: audit append failed for %s", action)


async def _require_active_tenant(store: InMemoryStore, tenant_id: str) -> None:
    # Shared preconditions for self-service joins (open / approval submit /
    # invite redeem): the tenant must exist and be active.
    status = await store.get_tenant_status(tenant_id)
    if status in (None, "deleted"):
        raise HTTPException(status_code=404, detail="tenant not found")
    if status != "active":
        raise HTTPException(status_code=409, detail="tenant is not active")


@router.post("/api/v1/tenants/{tenant_id}/invites", status_code=201)
async def create_invite(
    tenant_id: str,
    body: InviteCreate,
    store: InMemoryStore = Depends(get_store),
    claims: dict[str, Any] = Depends(require_tenant_admin_of()),
) -> dict[str, Any]:
    # Channel `invite`: tenant_admin mints a single-use expiring token with a
    # pre-assigned role. The raw token is returned EXACTLY ONCE (sha256 at
    # rest, same discipline as api keys and email verification tokens).
    status = await store.get_tenant_status(tenant_id)
    if status in (None, "deleted"):
        raise HTTPException(status_code=404, detail="tenant not found")
    token = INVITE_PREFIX + secrets.token_urlsafe(32)
    invite = await store.create_invite(
        "inv_" + secrets.token_hex(6),
        tenant_id,
        _hash_token(token),
        body.role,
        time.time() + body.ttl_seconds,
        email=body.email,
        created_by=claims.get("sub"),
    )
    await _audit(
        store,
        tenant_id,
        "member.invited",
        claims.get("sub"),
        {"invite_id": invite["invite_id"], "role": body.role, "email": body.email},
    )
    logger.info(
        "create_invite: tenant=%s invite=%s role=%s", tenant_id, invite["invite_id"], body.role
    )
    return {
        "invite_id": invite["invite_id"],
        "tenant_id": tenant_id,
        "role": body.role,
        "email": body.email,
        "expires_at": invite["expires_at"],
        "token": token,
    }


@router.get("/api/v1/tenants/{tenant_id}/invites")
async def list_invites(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict[str, Any] = Depends(require_tenant_admin_of()),
) -> list[dict[str, Any]]:
    # Inventory only — token hashes never leave the store.
    return [
        {k: v for k, v in inv.items() if k != "token_hash"}
        for inv in await store.list_invites(tenant_id)
    ]


@router.post("/api/v1/auth/invites/redeem")
async def redeem_invite(
    body: InviteRedeemRequest,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    claims: dict[str, Any] = Depends(require_bearer),
) -> dict[str, Any]:
    # Channel `invite` redemption. Requires a bearer (the redeemer is an
    # existing global user joining an additional tenant). Single-use +
    # expiry are enforced atomically by the store.
    user_id = claims.get("sub")
    await check_login_rate(request, "invite-redeem", user_id or "anonymous")
    invite = await store.get_invite_by_hash(_hash_token(body.token))
    if invite is None:
        logger.warning("redeem_invite: no matching invite")
        raise HTTPException(status_code=400, detail="invalid or expired invite token")
    if invite["used_at"] is not None:
        raise HTTPException(status_code=400, detail="invalid or expired invite token")
    if _invite_expired(invite["expires_at"]):
        raise HTTPException(status_code=400, detail="invalid or expired invite token")
    tenant_id = invite["tenant_id"]
    await _require_active_tenant(store, tenant_id)
    if await store.get_member_role(tenant_id, user_id) is not None:
        raise HTTPException(status_code=409, detail="already a member of this tenant")
    await store.add_member(tenant_id, user_id, invite["role"], added_by=user_id)
    await store.mark_invite_used(invite["invite_id"], user_id)
    await _audit(
        store,
        tenant_id,
        "member.joined",
        user_id,
        {"invite_id": invite["invite_id"], "role": invite["role"]},
    )
    logger.info("redeem_invite: tenant=%s user=%s role=%s", tenant_id, user_id, invite["role"])
    return {"tenant_id": tenant_id, "role": invite["role"], "joined": True}


@router.post("/api/v1/auth/tenants/{tenant_id}/join", status_code=201)
async def self_join(
    tenant_id: str,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    claims: dict[str, Any] = Depends(require_bearer),
) -> dict[str, Any]:
    # Channel `open`: self-service join, role FORCED to member (a caller can
    # never self-assign a privileged role). Rate-limited like login.
    user_id = claims.get("sub")
    await check_login_rate(request, "self-join", user_id or "anonymous")
    tenant = await store.get_tenant(tenant_id)
    if tenant is None or tenant.get("status") == "deleted":
        raise HTTPException(status_code=404, detail="tenant not found")
    if tenant.get("status") != "active":
        raise HTTPException(status_code=409, detail="tenant is not active")
    if tenant.get("join_policy") != "open":
        logger.warning(
            "self_join: tenant=%s join_policy=%s rejects self-join",
            tenant_id,
            tenant.get("join_policy"),
        )
        raise HTTPException(
            status_code=403,
            detail="tenant join policy does not allow self-service joining",
        )
    if await store.get_member_role(tenant_id, user_id) is not None:
        raise HTTPException(status_code=409, detail="already a member of this tenant")
    await store.add_member(tenant_id, user_id, "member", added_by=user_id)
    await _audit(store, tenant_id, "member.self_added", user_id, {"role": "member"})
    logger.info("self_join: tenant=%s user=%s", tenant_id, user_id)
    return {"tenant_id": tenant_id, "role": "member", "joined": True}


class JoinRequestSubmit(BaseModel):
    note: str | None = Field(default=None, max_length=512)


@router.post("/api/v1/tenants/{tenant_id}/join-requests", status_code=201)
async def submit_join_request(
    tenant_id: str,
    request: Request,
    body: JoinRequestSubmit | None = None,
    store: InMemoryStore = Depends(get_store),
    claims: dict[str, Any] = Depends(require_bearer),
) -> dict[str, Any]:
    # Channel `approval`: submit a join request. The admin decides later;
    # approval adds the member with role member.
    user_id = claims.get("sub")
    await check_login_rate(request, "join-request", user_id or "anonymous")
    tenant = await store.get_tenant(tenant_id)
    if tenant is None or tenant.get("status") == "deleted":
        raise HTTPException(status_code=404, detail="tenant not found")
    if tenant.get("status") != "active":
        raise HTTPException(status_code=409, detail="tenant is not active")
    if tenant.get("join_policy") != "approval":
        raise HTTPException(
            status_code=403,
            detail="tenant join policy does not accept join requests",
        )
    if await store.get_member_role(tenant_id, user_id) is not None:
        raise HTTPException(status_code=409, detail="already a member of this tenant")
    try:
        rec = await store.create_join_request("jreq_" + secrets.token_hex(6), tenant_id, user_id)
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit(store, tenant_id, "join.requested", user_id, {"request_id": rec["request_id"]})
    logger.info("submit_join_request: tenant=%s user=%s", tenant_id, user_id)
    return rec


@router.get("/api/v1/tenants/{tenant_id}/join-requests")
async def list_join_requests(
    tenant_id: str,
    status: str | None = None,
    store: InMemoryStore = Depends(get_store),
    _claims: dict[str, Any] = Depends(require_tenant_admin_of()),
) -> list[dict[str, Any]]:
    return await store.list_join_requests(tenant_id, status)


@router.post("/api/v1/tenants/{tenant_id}/join-requests/{request_id}/approve")
async def approve_join_request(
    tenant_id: str,
    request_id: str,
    store: InMemoryStore = Depends(get_store),
    claims: dict[str, Any] = Depends(require_tenant_admin_of()),
) -> dict[str, Any]:
    rec = await store.get_join_request(request_id)
    if rec is None or rec["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="join request not found")
    try:
        rec = await store.decide_join_request(request_id, "approved", claims.get("sub"))
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    # Approval IS the membership grant (role member — admins grant elevated
    # roles afterwards through the ordinary members API).
    if await store.get_member_role(tenant_id, rec["user_id"]) is None:
        await store.add_member(tenant_id, rec["user_id"], "member", added_by=claims.get("sub"))
    await _audit(
        store,
        tenant_id,
        "join.approved",
        claims.get("sub"),
        {"request_id": request_id, "user_id": rec["user_id"]},
    )
    logger.info("approve_join_request: request=%s tenant=%s", request_id, tenant_id)
    return rec


@router.post("/api/v1/tenants/{tenant_id}/join-requests/{request_id}/reject")
async def reject_join_request(
    tenant_id: str,
    request_id: str,
    store: InMemoryStore = Depends(get_store),
    claims: dict[str, Any] = Depends(require_tenant_admin_of()),
) -> dict[str, Any]:
    rec = await store.get_join_request(request_id)
    if rec is None or rec["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="join request not found")
    try:
        rec = await store.decide_join_request(request_id, "rejected", claims.get("sub"))
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit(
        store,
        tenant_id,
        "join.rejected",
        claims.get("sub"),
        {"request_id": request_id, "user_id": rec["user_id"]},
    )
    logger.info("reject_join_request: request=%s tenant=%s", request_id, tenant_id)
    return rec
