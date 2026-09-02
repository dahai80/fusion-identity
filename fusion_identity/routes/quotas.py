from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity.deps import (
    get_store,
    invalidate_tenant_api_keys_cache,
    require_tenant_admin_of,
)
from fusion_identity.models import QuotaUpdate
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)
_admin = require_tenant_admin_of("tenant_id")
router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/quotas", tags=["quotas"])


@router.get("")
async def get_quota(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    q = await store.get_quota(tenant_id)
    if not q:
        raise HTTPException(status_code=404, detail="tenant not found")
    return q


@router.put("")
async def put_quota(
    tenant_id: str,
    body: QuotaUpdate,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, Any]:
    fields = body.model_dump(exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="no fields to update")
    q = await store.put_quota(tenant_id, **fields)
    if not q:
        raise HTTPException(status_code=404, detail="tenant not found")
    # A5/L4: invalidation is security-critical. Fail visibly (500) rather than
    # swallowing — a swallowed failure would let the gRPC plane authorize on
    # the old lenient quota for up to 300s.
    try:
        await invalidate_tenant_api_keys_cache(request, tenant_id)
    except Exception as exc:
        logger.error("quota update: cache invalidation failed tenant=%s err=%s", tenant_id, exc)
        raise HTTPException(
            status_code=500,
            detail="quota updated but cache invalidation failed — may serve stale quota",
        ) from exc
    return q
