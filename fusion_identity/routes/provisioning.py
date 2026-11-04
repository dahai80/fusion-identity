from __future__ import annotations

import logging
import secrets
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from fusion_identity.deps import (
    get_settings,
    get_store,
    invalidate_tenant_cache,
    require_service_token,
)
from fusion_identity.events import (
    EVENT_APIKEY_CREATED,
    EVENT_TENANT_CREATED,
    dispatch_hook,
    emit_event,
)
from fusion_identity.store import DEFAULT_QUOTA, InMemoryStore, StoreConflict

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["provisioning"],
    dependencies=[Depends(require_service_token)],
)

_QUOTA_KEYS = (
    "rpm",
    "tpm",
    "concurrent",
    "storage_mb",
    "allowed_models",
    "allowed_modules",
    "default_priority",
)


class PlanTemplateUpdate(BaseModel):
    quota: dict[str, Any] = Field(default_factory=dict)


class SeedAdminSpec(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str | None = Field(default=None, min_length=12, max_length=256)
    email: str | None = None
    # Issue #39: privileged provision path keeps users verified (default);
    # the public tenant-signup wrapper passes False when email verification
    # is required so the seed admin cannot skip inbox confirmation.
    email_verified: bool = True


class ApiKeySpec(BaseModel):
    name: str | None = None
    scopes: list[str] = Field(default_factory=list)


class ProvisionRequest(BaseModel):
    # Issue #14 (M-A): one-shot tenant provisioning. `tpm` in quotas is the
    # DAILY token limit (legacy field name, kept for compatibility).
    tenant_id: str | None = Field(default=None, min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    plan: str = Field(default="standard", max_length=32)
    quotas: dict[str, Any] | None = None
    seed_admin: SeedAdminSpec | None = None
    api_key: ApiKeySpec | None = None
    hook_url: str | None = Field(default=None, max_length=2048)


def _effective_quota(
    template: dict[str, Any] | None,
    overrides: dict[str, Any] | None,
) -> dict[str, Any]:
    quota = dict(template or DEFAULT_QUOTA)
    for k in _QUOTA_KEYS:
        if overrides and k in overrides and overrides[k] is not None:
            quota[k] = overrides[k]
    return quota


async def provision_core(
    store: InMemoryStore,
    settings: Any,
    request: Request | None,
    *,
    tenant_id: str | None,
    display_name: str,
    plan: str,
    quotas: dict[str, Any] | None,
    seed_admin: SeedAdminSpec | None,
    api_key: ApiKeySpec | None,
    hook_url: str | None,
    endpoint: str,
    idempotency_key: str | None,
    added_by: str | None = None,
) -> dict[str, Any]:
    # Issue #39: extracted from provision_tenant so the public tenant-signup
    # route reuses the EXACT same creation path (acceptance: zero duplicated
    # tenant-creation logic). request is optional so callers without a tenant
    # cache can still provision. added_by is FK-attributed to users(user_id):
    # callers either pass a real user id or None — a literal like "provision"
    # would violate tenant_members.added_by_fkey on Postgres (InMemory cannot
    # catch this; found by live-PG verification of the register-tenant flow).
    if idempotency_key:
        cached = await store.get_idempotency(f"{endpoint}:{idempotency_key}")
        if cached is not None:
            logger.info("provision: idempotent replay key=%s", idempotency_key)
            out = dict(cached["response"])
            out["idempotent_replay"] = True
            return out

    tid = tenant_id or ("tnt_" + secrets.token_hex(6))
    template = await store.get_plan_template(plan)
    quota = _effective_quota(template, quotas)

    # Pre-flight the seed-admin username so a conflict fails BEFORE the tenant
    # is created — a partial provision would otherwise orphan the tenant and
    # poison the idempotency replay with a 409.
    if seed_admin is not None:
        existing = await store.get_user_by_username(seed_admin.username)
        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail=f"username {seed_admin.username!r} already exists",
            )

    try:
        tenant = await store.create_tenant(tid, display_name=display_name, plan=plan)
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    quota = await store.put_quota(tid, **quota) or {}

    admin_out: dict[str, Any] | None = None
    if seed_admin is not None:
        generated = seed_admin.password is None
        password = seed_admin.password or secrets.token_urlsafe(18)
        user_id = "usr_" + secrets.token_hex(6)
        user = await store.create_user(
            user_id,
            seed_admin.username,
            password,
            email=seed_admin.email,
            must_change_password=generated,
            email_verified=seed_admin.email_verified,
        )
        await store.add_member(tid, user_id, "tenant_admin", added_by=added_by)
        admin_out = {
            "user_id": user["user_id"],
            "username": user["username"],
            "must_change_password": generated,
            "initial_password": password,
        }
        logger.info("provision: seed admin tenant=%s user=%s", tid, user_id)

    api_key_out: dict[str, Any] | None = None
    if api_key is not None:
        raw, record = await store.create_api_key(
            tid, admin_out["user_id"] if admin_out else None, scopes=api_key.scopes
        )
        api_key_out = {k: v for k, v in record.items() if k != "key_hash"}
        api_key_out["raw_key"] = raw
        logger.info("provision: api key tenant=%s key=%s", tid, record["key_id"])

    result: dict[str, Any] = {
        "tenant": tenant,
        "quota": quota,
        "admin": admin_out,
        "api_key": api_key_out,
    }

    await emit_event(
        store,
        EVENT_TENANT_CREATED,
        tid,
        {"tenant_id": tid, "plan": plan, "display_name": display_name},
    )
    if api_key_out is not None:
        await emit_event(
            store,
            EVENT_APIKEY_CREATED,
            tid,
            {
                "tenant_id": tid,
                "key_id": api_key_out["key_id"],
                "prefix": api_key_out["prefix"],
            },
        )

    if hook_url:
        # Issue #14 (M-D): delegate downstream key registration to a generic
        # signed hook. The raw api key travels only in the hook/response, never
        # in outbox events.
        hook_payload = {
            "tenant": tenant,
            "quota": quota,
            "admin": {k: v for k, v in (admin_out or {}).items() if k != "initial_password"},
            "api_key": api_key_out,
        }
        hook_result = await dispatch_hook(
            hook_url,
            settings.webhook_secret or settings.service_token,
            "provision.completed",
            hook_payload,
        )
        result["hook"] = {"url": hook_url, **hook_result}

    if idempotency_key:
        await store.put_idempotency(f"{endpoint}:{idempotency_key}", endpoint, result)
    if request is not None:
        await invalidate_tenant_cache(request, tid)
    logger.info("provision: done tenant=%s plan=%s", tid, plan)
    result["idempotent_replay"] = False
    return result


@router.post("/tenants/provision", status_code=201)
async def provision_tenant(
    body: ProvisionRequest,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    settings = get_settings(request)
    return await provision_core(
        store,
        settings,
        request,
        tenant_id=body.tenant_id,
        display_name=body.display_name,
        plan=body.plan,
        quotas=body.quotas,
        seed_admin=body.seed_admin,
        api_key=body.api_key,
        hook_url=body.hook_url,
        endpoint="/api/v1/admin/tenants/provision",
        idempotency_key=idempotency_key,
    )


@router.get("/plan-templates")
async def list_plan_templates(
    store: InMemoryStore = Depends(get_store),
) -> list[dict[str, Any]]:
    return await store.list_plan_templates()


@router.get("/plan-templates/{plan}")
async def get_plan_template(
    plan: str,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    quota = await store.get_plan_template(plan)
    if quota is None:
        raise HTTPException(status_code=404, detail=f"plan template {plan!r} not found")
    return {"plan": plan, "quota": quota}


@router.put("/plan-templates/{plan}")
async def put_plan_template(
    plan: str,
    body: PlanTemplateUpdate,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    try:
        quota = await store.put_plan_template(plan, body.quota)
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"plan": plan, "quota": quota}


@router.get("/events")
async def list_events(
    store: InMemoryStore = Depends(get_store),
    cursor: int = 0,
    limit: int = 100,
) -> dict[str, Any]:
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=422, detail="limit must be 1..1000")
    events = await store.list_events(cursor=cursor, limit=limit)
    next_cursor = events[-1]["seq"] if events else cursor
    return {"events": events, "next_cursor": next_cursor}
