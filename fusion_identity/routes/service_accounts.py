from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from fusion_identity.deps import get_store, require_service_token
from fusion_identity.ratelimit import check_login_rate
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

# Issue #76: headless service accounts for acceptance suites / CI clients.
# Owner verdict on fusion-site#37 — NO captcha backdoor: machines authenticate
# through the identity chain with a pre-provisioned, revocable, audit-visible
# credential.

_SVC_AUTH = dict(dependencies=[Depends(require_service_token)])

admin_router = APIRouter(
    prefix="/api/v1/admin",
    tags=["service-accounts"],
    **_SVC_AUTH,
)

auth_router = APIRouter(prefix="/api/v1/auth", tags=["service-accounts"])


class ServiceAccountCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    scopes: list[str] = Field(default_factory=list, max_length=32)


class ServiceAccountTokenRequest(BaseModel):
    credential: str = Field(min_length=8, max_length=256)


async def _require_tenant(store, tenant_id: str) -> dict:
    tenant = await store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="tenant not found")
    return tenant


@admin_router.post("/tenants/{tenant_id}/service-accounts")
async def create_service_account(
    tenant_id: str,
    body: ServiceAccountCreate,
    store: InMemoryStore = Depends(get_store),
):
    await _require_tenant(store, tenant_id)
    raw, rec = await store.create_service_account(tenant_id, body.name, body.scopes, None)
    await store.append_audit(
        tenant_id,
        None,
        None,
        "service",
        "svc.created",
        rec["account_id"],
        {"name": body.name, "scopes": body.scopes},
    )
    logger.info(
        "service account created: tenant=%s account=%s name=%s",
        tenant_id,
        rec["account_id"],
        body.name,
    )
    # Never echo the stored hash — the raw credential is the only secret.
    safe = {k: v for k, v in rec.items() if k != "cred_hash"}
    return {"credential": raw, **safe}


@admin_router.get("/tenants/{tenant_id}/service-accounts")
async def list_service_accounts(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
):
    await _require_tenant(store, tenant_id)
    return await store.list_service_accounts(tenant_id)


@admin_router.delete("/tenants/{tenant_id}/service-accounts/{account_id}")
async def revoke_service_account(
    tenant_id: str,
    account_id: str,
    store: InMemoryStore = Depends(get_store),
):
    await _require_tenant(store, tenant_id)
    rec = await store.get_service_account(account_id)
    if not rec or rec["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="service account not found")
    revoked = await store.revoke_service_account(account_id)
    if not revoked:
        raise HTTPException(status_code=409, detail="service account already revoked")
    await store.append_audit(
        tenant_id,
        None,
        None,
        "service",
        "svc.revoked",
        account_id,
        {"name": rec["name"]},
    )
    logger.info("service account revoked: tenant=%s account=%s", tenant_id, account_id)
    return {"account_id": account_id, "status": "revoked"}


@auth_router.post("/service-accounts/token")
async def service_account_token(
    request: Request,
    body: ServiceAccountTokenRequest,
):
    # Tenant-middleware-exempt: the credential itself is the secret. Scoped
    # short-TTL access token only — no refresh (machines re-exchange).
    await check_login_rate(request, "_service_account", None)
    return await request.app.state.auth_service.service_account_token(body.credential)
