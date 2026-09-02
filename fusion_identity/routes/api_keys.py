from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from fusion_identity.deps import get_store, require_tenant_admin_of
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
    raw, rec = await store.create_api_key(tenant_id, None, body.scopes)
    return ApiKeyResponse(
        key_id=rec["key_id"], raw_key=raw, prefix=rec["prefix"], scopes=rec["scopes"]
    )


@router.delete("/{key_id}")
async def revoke_api_key(
    tenant_id: str,
    key_id: str,
    store: InMemoryStore = Depends(get_store),
    _claims: dict = Depends(_admin),
) -> dict[str, bool]:
    rec = next((k for k in await store.list_api_keys(tenant_id) if k["key_id"] == key_id), None)
    if not rec:
        raise HTTPException(status_code=404, detail="api key not found")
    ok = await store.revoke_api_key(key_id)
    return {"revoked": ok}
