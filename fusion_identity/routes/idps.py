from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity.crypto import encrypt_secret
from fusion_identity.deps import get_settings, require_tenant_admin_of
from fusion_identity.models import IdpCreate, IdpResponse, IdpUpdate
from fusion_identity.store import StoreConflict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/idps", tags=["idps"])


def _settings(request: Request) -> Any:
    return get_settings(request)


@router.get("", response_model=list[IdpResponse])
async def list_idps(
    tenant_id: str,
    request: Request,
    _: dict[str, Any] = Depends(require_tenant_admin_of("tenant_id")),
) -> list[dict[str, Any]]:
    store = request.app.state.store
    rows = await store.list_idps(tenant_id)
    logger.info("list_idps: tenant=%s count=%d", tenant_id, len(rows))
    return rows


@router.post("", response_model=IdpResponse, status_code=201)
async def create_idp(
    tenant_id: str,
    req: IdpCreate,
    request: Request,
    _: dict[str, Any] = Depends(require_tenant_admin_of("tenant_id")),
) -> dict[str, Any]:
    store = request.app.state.store
    tenant = await store.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    kek = _settings(request).kek
    enc = encrypt_secret(req.client_secret, kek) if req.client_secret else None
    try:
        rec = await store.create_idp(
            req.idp_id,
            tenant_id,
            type=req.type,
            issuer_url=req.issuer_url,
            client_id=req.client_id,
            client_secret_enc=enc,
            scopes=req.scopes,
            auto_provision=req.auto_provision,
        )
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    logger.warning("create_idp: tenant=%s idp=%s type=%s", tenant_id, req.idp_id, req.type)
    await store.append_audit(
        tenant_id, None, None, None, "idp.create", "idp", {"idp_id": req.idp_id}
    )
    rec.pop("client_secret_enc", None)
    return rec


@router.get("/{idp_id}", response_model=IdpResponse)
async def get_idp(
    tenant_id: str,
    idp_id: str,
    request: Request,
    _: dict[str, Any] = Depends(require_tenant_admin_of("tenant_id")),
) -> dict[str, Any]:
    store = request.app.state.store
    rec = await store.get_idp(idp_id)
    if rec is None or rec["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="idp not found")
    rec.pop("client_secret_enc", None)
    logger.info("get_idp: tenant=%s idp=%s", tenant_id, idp_id)
    return rec


@router.patch("/{idp_id}", response_model=IdpResponse)
async def update_idp(
    tenant_id: str,
    idp_id: str,
    req: IdpUpdate,
    request: Request,
    _: dict[str, Any] = Depends(require_tenant_admin_of("tenant_id")),
) -> dict[str, Any]:
    store = request.app.state.store
    rec = await store.get_idp(idp_id)
    if rec is None or rec["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="idp not found")
    kek = _settings(request).kek
    fields: dict[str, Any] = {}
    if req.type is not None:
        fields["type"] = req.type
    if req.issuer_url is not None:
        fields["issuer_url"] = req.issuer_url
    if req.client_id is not None:
        fields["client_id"] = req.client_id
    if req.client_secret is not None:
        fields["client_secret_enc"] = encrypt_secret(req.client_secret, kek)
    if req.scopes is not None:
        fields["scopes"] = req.scopes
    if req.auto_provision is not None:
        fields["auto_provision"] = req.auto_provision
    updated = await store.update_idp(idp_id, **fields)
    logger.warning("update_idp: tenant=%s idp=%s fields=%s", tenant_id, idp_id, list(fields))
    await store.append_audit(
        tenant_id, None, None, None, "idp.update", "idp", {"idp_id": idp_id, "fields": list(fields)}
    )
    out = dict(updated or rec)
    out.pop("client_secret_enc", None)
    return out


@router.delete("/{idp_id}")
async def delete_idp(
    tenant_id: str,
    idp_id: str,
    request: Request,
    _: dict[str, Any] = Depends(require_tenant_admin_of("tenant_id")),
) -> dict[str, Any]:
    store = request.app.state.store
    rec = await store.get_idp(idp_id)
    if rec is None or rec["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="idp not found")
    await store.delete_idp(idp_id)
    await store.append_audit(tenant_id, None, None, None, "idp.delete", "idp", {"idp_id": idp_id})
    logger.warning("delete_idp: tenant=%s idp=%s", tenant_id, idp_id)
    return {"deleted": True, "idp_id": idp_id}
