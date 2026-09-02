from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity.deps import get_cache, get_store, require_tenant_admin_of
from fusion_identity.models import ApiKeyCreate, ApiKeyResponse
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

_admin = require_tenant_admin_of("tenant_id")
router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/api-keys", tags=["api-keys"])

# M1: fields that must never leave the store on a list/export. key_hash is a
# credential fingerprint; leaking it lets an attacker skip the secret-knowledge
# check and forge cache lookups.
_API_KEY_DENYLIST = ("key_hash", "raw_key")


def _scrub_api_key(rec: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in rec.items() if k not in _API_KEY_DENYLIST}


@router.get("")
async def list_api_keys(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> list[dict[str, Any]]:
    keys = await store.list_api_keys(tenant_id)
    return [_scrub_api_key(k) for k in keys]


@router.post("", status_code=201, response_model=ApiKeyResponse)
async def create_api_key(
    tenant_id: str,
    body: ApiKeyCreate,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> ApiKeyResponse:
    raw, rec = await store.create_api_key(tenant_id, _claims.get("sub"), body.scopes)
    await store.append_audit(
        tenant_id,
        _claims.get("sub"),
        None,
        _claims.get("role"),
        "apikey.create",
        "api_key",
        {"key_id": rec["key_id"]},
    )
    return ApiKeyResponse(
        key_id=rec["key_id"],
        raw_key=raw,
        prefix=rec["prefix"],
        scopes=rec["scopes"],
        user_id=rec.get("user_id"),
    )


@router.delete("/{key_id}")
async def revoke_api_key(
    tenant_id: str,
    key_id: str,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, bool]:
    rec = next((k for k in await store.list_api_keys(tenant_id) if k["key_id"] == key_id), None)
    if not rec:
        raise HTTPException(status_code=404, detail="api key not found")
    ok = await store.revoke_api_key(key_id)
    cache = get_cache(request)
    if cache is not None and rec.get("key_hash"):
        # P2-11: fail-closed — a cache-invalidation failure leaves the revoked
        # key authorized for up to 300s. Surface a 500 so the operator knows the
        # revocation is not yet effective, instead of silently log-and-continue.
        try:
            await cache.invalidate_api_key_by_hash(rec["key_hash"])
        except Exception as exc:
            logger.error("revoke_api_key: cache invalidate failed (fail-closed): %s", exc)
            raise HTTPException(
                status_code=500,
                detail=(
                    "api key revoked but cache invalidation failed — key may remain valid up to TTL"
                ),
            ) from exc
    await store.append_audit(
        tenant_id,
        _claims.get("sub"),
        None,
        _claims.get("role"),
        "apikey.revoke",
        "api_key",
        {"key_id": key_id},
    )
    return {"revoked": ok}
