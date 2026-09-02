from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity.deps import get_cache, get_store, require_tenant_admin_of
from fusion_identity.models import ApiKeyCreate, ApiKeyResponse
from fusion_identity.store import InMemoryStore

_admin = require_tenant_admin_of("tenant_id")
router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/api-keys", tags=["api-keys"])


@router.get("")
async def list_api_keys(
    tenant_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> list[dict[str, Any]]:
    return await store.list_api_keys(tenant_id)


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
        try:
            await cache.invalidate_api_key_by_hash(rec["key_hash"])
        except Exception as exc:
            import logging

            logging.getLogger(__name__).warning("revoke_api_key: cache invalidate err=%s", exc)
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
