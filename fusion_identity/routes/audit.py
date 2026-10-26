from __future__ import annotations

import hmac
import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from fusion_identity.deps import (
    get_settings,
    get_store,
    require_permission_of,
    require_service_token,
)
from fusion_identity.models import AuditEventIn, BusinessAuditEventIn
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

# Issue #16: audit log is read-only for operator + tenant_admin via matrix.
_read = require_permission_of("audit", "read")
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
    return await _read(request, x_tenant_id=x_tenant_id, authorization=authorization)


require_admin_or_service.__fusion_guard__ = ("audit", "read")


@router.get("")
async def list_audit(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_read),
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
    _claims: dict = Depends(_read),
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


_BIZ_SOURCE = "business"
_BIZ_PAGE = 1000
_BIZ_MAX_PAGES = 20


@router.post("/business-events", status_code=201)
async def append_business_event(
    tenant_id: str,
    body: BusinessAuditEventIn,
    store: InMemoryStore = Depends(get_store),
    _svc: None = Depends(require_service_token),
) -> dict[str, Any]:
    # Issue #18: business apps (e.g. ai-speech-exam) append audit events into
    # the identity hash chain — tamper evidence stays here, apps never
    # self-maintain chains. Required fields map onto chain-covered storage:
    # actor -> user_id, object_id -> resource, the rest ride in detail.
    t = await store.get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="tenant not found")
    action = body.action if body.action.startswith("external.") else f"external.{body.action}"
    detail = {
        "source": _BIZ_SOURCE,
        "trace_id": body.trace_id,
        "client_ts": body.timestamp,
        "actor": body.actor,
        "object_id": body.object_id,
        "severity": body.severity,
        "payload": body.payload,
    }
    rec = await store.append_audit(
        tenant_id, body.actor, None, "service", action, body.object_id, detail
    )
    logger.info(
        "append_business_event: tenant=%s actor=%s action=%s trace=%s seq=%s",
        tenant_id,
        body.actor,
        action,
        body.trace_id,
        rec.get("seq"),
    )
    return {
        "seq": rec.get("seq"),
        "chain_hash": rec.get("chain_hash"),
        "action": action,
        "ts": rec.get("ts"),
        "trace_id": body.trace_id,
    }


def _biz_match(
    a: dict[str, Any],
    actor: str | None,
    action: str | None,
    object_id: str | None,
    trace_id: str | None,
) -> bool:
    detail = a.get("detail") or {}
    if not isinstance(detail, dict) or detail.get("source") != _BIZ_SOURCE:
        return False
    if actor is not None and a.get("user_id") != actor:
        return False
    if action is not None and not str(a.get("action", "")).endswith(action):
        return False
    if object_id is not None and a.get("resource") != object_id:
        return False
    if trace_id is not None:
        return detail.get("trace_id") == trace_id
    return True


async def _biz_query(
    store: InMemoryStore,
    tenant_id: str,
    *,
    actor: str | None,
    action: str | None,
    object_id: str | None,
    trace_id: str | None,
    since: float | None,
    until: float | None,
    limit: int,
) -> tuple[list[dict[str, Any]], bool]:
    # Filtered scan: walk the ledger newest-first page by page until `limit`
    # matches accumulate or the ledger is exhausted. `truncated` reports the
    # latter case so compliance callers know to narrow filters.
    out: list[dict[str, Any]] = []
    cursor: int | None = None
    for _ in range(_BIZ_MAX_PAGES):
        rows = await store.list_audit(
            tenant_id, limit=_BIZ_PAGE, since=since, until=until, cursor=cursor
        )
        if not rows:
            return out, False
        for a in rows:
            if _biz_match(a, actor, action, object_id, trace_id):
                out.append(a)
                if len(out) >= limit:
                    return out, False
        cursor = rows[-1]["id"]
    logger.warning(
        "_biz_query: tenant=%s hit page cap (%d pages) — narrow filters", tenant_id, _BIZ_MAX_PAGES
    )
    return out, True


@router.get("/business-events")
async def list_business_events(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_read),
    actor: str | None = Query(default=None),
    action: str | None = Query(default=None),
    object_id: str | None = Query(default=None),
    trace_id: str | None = Query(default=None),
    since: float | None = Query(default=None),
    until: float | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    # Issue #18: compliance query surface — filter business events by any
    # combination of actor / action / object_id / trace_id plus time window.
    events, truncated = await _biz_query(
        store,
        tenant_id,
        actor=actor,
        action=action,
        object_id=object_id,
        trace_id=trace_id,
        since=since,
        until=until,
        limit=limit,
    )
    logger.info(
        "list_business_events: tenant=%s count=%d filters(actor=%s action=%s obj=%s trace=%s)",
        tenant_id,
        len(events),
        actor,
        action,
        object_id,
        trace_id,
    )
    return {"events": events, "count": len(events), "truncated": truncated}


@router.get("/export")
async def export_audit(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    claims: dict = Depends(require_admin_or_service),
    since: float | None = Query(default=None),
    until: float | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=10000),
) -> dict[str, Any]:
    # Issue #18: compliance export — full audit ledger slice plus the live
    # chain-verification verdict, so a reviewer can prove integrity of the
    # exact exported window's underlying chain in one round trip.
    chain = await store.verify_audit_chain(tenant_id)
    events = await store.list_audit(tenant_id, limit=limit, since=since, until=until)
    logger.info(
        "export_audit: tenant=%s count=%d chain_valid=%s by=%s",
        tenant_id,
        len(events),
        chain.get("valid"),
        claims.get("sub"),
    )
    return {
        "tenant_id": tenant_id,
        "generated_at": time.time(),
        "chain": chain,
        "count": len(events),
        "events": events,
    }


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
