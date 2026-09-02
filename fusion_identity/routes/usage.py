from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from fusion_identity.deps import get_store, require_service_token, require_tenant_admin_of
from fusion_identity.models import UsageEmit, UsageRecord
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}", tags=["usage"])

_admin = require_tenant_admin_of("tenant_id")


@router.post(
    "/usage",
    response_model=UsageRecord,
    dependencies=[Depends(require_service_token)],
)
async def emit_usage(
    tenant_id: str,
    body: UsageEmit,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    await store.record_usage(
        tenant_id,
        body.user_id,
        body.metric,
        body.value,
        body.source,
        body.model,
    )
    logger.info(
        "emit_usage: tenant=%s metric=%s value=%d source=%s",
        tenant_id,
        body.metric,
        body.value,
        body.source,
    )
    return {"metric": body.metric, "value": body.value}


@router.get("/usage", response_model=list[UsageRecord])
async def get_usage(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    since: float | None = Query(default=None),
    until: float | None = Query(default=None),
    metric: str | None = Query(default=None),
    _claims: dict = Depends(_admin),
) -> list[dict[str, Any]]:
    return await store.aggregate_usage(tenant_id, since=since, until=until, metric=metric)


@router.get("/config")
async def get_tenant_config(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    q = await store.get_quota(tenant_id) or {}
    return {
        "tenant_id": t["tenant_id"],
        "display_name": t["display_name"],
        "plan": t["plan"],
        "status": t["status"],
        "quota": q,
    }


@router.get("/export")
async def export_tenant(
    tenant_id: str,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    format: str = Query(default="json", pattern="^(json|csv)$"),
    _claims: dict = Depends(_admin),
) -> Any:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    members = await store.list_members(tenant_id)
    safe_members = [
        {k: v for k, v in m.items() if k not in ("password_hash", "password_hash_v", "salt")}
        for m in members
    ]
    api_keys = await store.list_api_keys(tenant_id)
    quota = await store.get_quota(tenant_id) or {}
    usage = await store.aggregate_usage(tenant_id)
    logger.info("export_tenant: tenant=%s by=%s format=%s", tenant_id, _claims.get("sub"), format)
    await store.append_audit(
        tenant_id,
        _claims.get("sub"),
        None,
        _claims.get("role"),
        "tenant.export",
        "tenant",
        {"members": len(safe_members), "api_keys": len(api_keys), "format": format},
    )
    payload = {
        "tenant": {
            "tenant_id": t["tenant_id"],
            "display_name": t["display_name"],
            "plan": t["plan"],
            "status": t["status"],
        },
        "members": safe_members,
        "api_keys": api_keys,
        "quota": quota,
        "usage": usage,
    }
    if format == "csv":
        return _export_csv(tenant_id, payload)
    return payload


def _export_csv(tenant_id: str, payload: dict[str, Any]) -> PlainTextResponse:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["section", "tenant_id", "field", "value"])
    for key in ("tenant_id", "display_name", "plan", "status"):
        writer.writerow(["tenant", tenant_id, key, payload["tenant"].get(key, "")])
    for m in payload["members"]:
        for k, v in m.items():
            writer.writerow(["member", tenant_id, k, v])
    for ak in payload["api_keys"]:
        for k, v in ak.items():
            writer.writerow(["api_key", tenant_id, k, v])
    for k, v in payload["quota"].items():
        val = json.dumps(v, default=str) if isinstance(v, (list, dict)) else v
        writer.writerow(["quota", tenant_id, k, val])
    for u in payload["usage"]:
        for k, v in u.items():
            writer.writerow(["usage", tenant_id, k, v])
    return PlainTextResponse(
        content=out.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=tenant_{tenant_id}_export.csv"},
    )
