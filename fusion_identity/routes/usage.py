from __future__ import annotations

import csv
import io
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from fusion_identity.deps import get_store, require_service_token, require_tenant_admin_of
from fusion_identity.models import UsageEmit, UsageRecord
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}", tags=["usage"])

_admin = require_tenant_admin_of("tenant_id")

# M1: credential/secret fields that must never appear in an export.
_EXPORT_DENYLIST = ("password_hash", "password_hash_v", "salt", "key_hash", "raw_key")
# P3: hard cap on usage rows materialized for an export so a tenant with a huge
# usage log cannot exhaust server memory.
_EXPORT_USAGE_CAP = 50000


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
    since: float | None = Query(default=None, description="usage epoch-seconds lower bound"),
    until: float | None = Query(default=None, description="usage epoch-seconds upper bound"),
    _claims: dict = Depends(_admin),
) -> Any:
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    members = await store.list_members(tenant_id)
    safe_members = [{k: v for k, v in m.items() if k not in _EXPORT_DENYLIST} for m in members]
    # M1: strip key_hash/raw_key from exported api keys.
    api_keys = [
        {k: v for k, v in ak.items() if k not in _EXPORT_DENYLIST}
        for ak in await store.list_api_keys(tenant_id)
    ]
    quota = await store.get_quota(tenant_id) or {}
    # P3: bound the usage window and the row count so a large tenant cannot
    # force the server to materialize an unbounded payload in memory.
    usage = await store.aggregate_usage(tenant_id, since=since, until=until)
    if len(usage) > _EXPORT_USAGE_CAP:
        usage = usage[:_EXPORT_USAGE_CAP]
        logger.warning(
            "export_tenant: usage capped to %d rows tenant=%s", _EXPORT_USAGE_CAP, tenant_id
        )
    logger.info(
        "export_tenant: tenant=%s by=%s format=%s since=%s until=%s usage_rows=%d",
        tenant_id,
        _claims.get("sub"),
        format,
        since,
        until,
        len(usage),
    )
    await store.append_audit(
        tenant_id,
        _claims.get("sub"),
        None,
        _claims.get("role"),
        "tenant.export",
        "tenant",
        {
            "members": len(safe_members),
            "api_keys": len(api_keys),
            "format": format,
            "usage_rows": len(usage),
            "since": since,
            "until": until,
        },
    )
    tenant_view = {
        "tenant_id": t["tenant_id"],
        "display_name": t["display_name"],
        "plan": t["plan"],
        "status": t["status"],
    }
    # P3: stream the response instead of buffering the whole payload, so large
    # tenants do not spike resident memory on export.
    if format == "csv":
        return _export_csv_stream(tenant_id, tenant_view, safe_members, api_keys, quota, usage)
    return _export_json_stream(tenant_view, safe_members, api_keys, quota, usage)


def _export_json_stream(
    tenant: dict[str, Any],
    members: list[dict[str, Any]],
    api_keys: list[dict[str, Any]],
    quota: dict[str, Any],
    usage: list[dict[str, Any]],
) -> StreamingResponse:
    payload = {
        "tenant": tenant,
        "members": members,
        "api_keys": api_keys,
        "quota": quota,
        "usage": usage,
    }
    body = json.dumps(payload, default=str).encode("utf-8")

    async def gen() -> AsyncIterator[bytes]:
        yield body

    return StreamingResponse(
        gen(),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=tenant_export.json"},
    )


def _export_csv_stream(
    tenant_id: str,
    tenant: dict[str, Any],
    members: list[dict[str, Any]],
    api_keys: list[dict[str, Any]],
    quota: dict[str, Any],
    usage: list[dict[str, Any]],
) -> StreamingResponse:
    async def gen() -> AsyncIterator[bytes]:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["section", "tenant_id", "field", "value"])
        for key in ("tenant_id", "display_name", "plan", "status"):
            writer.writerow(["tenant", tenant_id, key, tenant.get(key, "")])
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate()
        for m in members:
            for k, v in m.items():
                writer.writerow(["member", tenant_id, k, v])
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate()
        for ak in api_keys:
            for k, v in ak.items():
                writer.writerow(["api_key", tenant_id, k, v])
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate()
        for k, v in quota.items():
            val = json.dumps(v, default=str) if isinstance(v, (list, dict)) else v
            writer.writerow(["quota", tenant_id, k, val])
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate()
        for u in usage:
            for k, v in u.items():
                writer.writerow(["usage", tenant_id, k, v])
        yield buf.getvalue().encode("utf-8")

    return StreamingResponse(
        gen(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=tenant_{tenant_id}_export.csv"},
    )
