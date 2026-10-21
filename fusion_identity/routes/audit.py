from __future__ import annotations

import hmac
import logging
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from fusion_identity.deps import (
    get_settings,
    get_store,
    require_service_token,
    require_tenant_admin_of,
)
from fusion_identity.models import AuditEventIn
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

_admin = require_tenant_admin_of("tenant_id")
router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/audit", tags=["audit"])


async def require_admin_or_service(
    request: Request,
    x_tenant_id: str = Header(default=""),
    authorization: str = Header(default=""),
) -> dict[str, Any]:
    # Issue #10: OTLP export is pulled either by the tenant admin (browser /
    # console) or by the OTel collector holding the service token.
    if authorization:
        from fusion_identity.jwt_utils import JwtError, extract_bearer

        try:
            token = extract_bearer(authorization)
        except JwtError:
            token = ""
        if token and hmac.compare_digest(token, get_settings(request).service_token):
            return {"role": "service", "tid": x_tenant_id}
    return await _admin(request, x_tenant_id=x_tenant_id, authorization=authorization)


@router.get("")
async def list_audit(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
    limit: int = 100,
    since: float | None = None,
    until: float | None = None,
    cursor: int | None = None,
) -> list[dict[str, Any]]:
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be 1..1000")
    return await store.list_audit(
        tenant_id,
        limit=limit,
        since=since,
        until=until,
        cursor=cursor,
    )


@router.get("/verify")
async def verify_audit(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    return await store.verify_audit_chain(tenant_id)


_AUDIT_SEVERITY = {"ERROR": "ERROR", "FATAL": "FATAL", "WARN": "WARN"}


@router.post("/events", status_code=201)
async def ingest_event(
    tenant_id: str,
    body: AuditEventIn,
    store: InMemoryStore = Depends(get_store),
    _svc: None = Depends(require_service_token),
) -> dict[str, Any]:
    # Issue #10: consumers (e.g. fusion-cowork) push approval/permission/run
    # events into the hash-chained tenant audit ledger.
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    action = body.action if body.action.startswith("external.") else f"external.{body.action}"
    rec = await store.append_audit(
        tenant_id,
        body.user_id,
        None,
        "service",
        action,
        body.resource,
        {"severity": body.severity, **body.detail},
    )
    logger.info("ingest_event: tenant=%s action=%s seq=%s", tenant_id, action, rec.get("seq"))
    return {"seq": rec.get("seq"), "chain_hash": rec.get("chain_hash"), "action": action}


@router.get("/otlp")
async def export_otlp(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(require_admin_or_service),
    limit: int = Query(default=500, ge=1, le=1000),
    since: float | None = Query(default=None),
) -> dict[str, Any]:
    # Issue #10: OTLP/JSON logs export so a local OTel Collector can forward
    # audit events to SIEM without any cloud dependency.
    rows = await store.list_audit(tenant_id, limit=limit, since=since, until=None)
    log_records = []
    for a in rows:
        detail = a.get("detail")
        attrs = [
            {"key": "tenant.id", "value": {"stringValue": a.get("tenant_id", "")}},
            {"key": "audit.seq", "value": {"intValue": str(a.get("seq", 0))}},
            {"key": "audit.resource", "value": {"stringValue": str(a.get("resource") or "")}},
            {"key": "audit.role", "value": {"stringValue": str(a.get("role") or "")}},
        ]
        if a.get("user_id"):
            attrs.append({"key": "user.id", "value": {"stringValue": a["user_id"]}})
        if a.get("jti"):
            attrs.append({"key": "audit.jti", "value": {"stringValue": a["jti"]}})
        if detail is not None:
            import json

            attrs.append({"key": "audit.detail", "value": {"stringValue": json.dumps(detail)}})
        log_records.append(
            {
                "timeUnixNano": str(int(a.get("ts", 0) * 1_000_000_000)),
                "severityText": _AUDIT_SEVERITY.get(
                    (detail or {}).get("severity", "INFO") if isinstance(detail, dict) else "INFO",
                    "INFO",
                ),
                "body": {"stringValue": str(a.get("action", ""))},
                "attributes": attrs,
            }
        )
    logger.info(
        "export_otlp: tenant=%s records=%d by=%s", tenant_id, len(log_records), claims.get("sub")
    )
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "fusion-identity"}},
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "fusion-identity.audit"},
                        "logRecords": log_records,
                    }
                ],
            }
        ]
    }
