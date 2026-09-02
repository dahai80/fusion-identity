from __future__ import annotations

import hmac
import logging
from typing import Any

from fastapi import Header, HTTPException, Request

from fusion_identity.auth import AuthService
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)


def get_store(request: Request) -> InMemoryStore:
    store = getattr(request.app.state, "store", None)
    if store is None:
        raise HTTPException(status_code=500, detail="store not initialized")
    return store


def get_auth_service(request: Request) -> AuthService:
    svc = getattr(request.app.state, "auth_service", None)
    if svc is None:
        raise HTTPException(status_code=500, detail="auth service not initialized")
    return svc


def get_settings(request: Request):
    s = getattr(request.app.state, "settings", None)
    if s is None:
        raise HTTPException(status_code=500, detail="settings not initialized")
    return s


async def require_tenant_admin(
    request: Request,
    x_tenant_id: str = Header(default=""),
    authorization: str = Header(default=""),
) -> dict[str, Any]:
    claims = await _resolve_admin(request, x_tenant_id, authorization)
    return claims


def require_tenant_admin_of(tenant_id_param: str = "tenant_id"):
    async def _dep(
        request: Request,
        x_tenant_id: str = Header(default=""),
        authorization: str = Header(default=""),
    ) -> dict[str, Any]:
        claims = await _resolve_admin(request, x_tenant_id, authorization)
        path_tenant = request.path_params.get(tenant_id_param)
        if path_tenant is not None and claims["tid"] != path_tenant:
            logger.warning(
                "cross-tenant blocked: token tid=%s path %s=%s",
                claims["tid"],
                tenant_id_param,
                path_tenant,
            )
            raise HTTPException(status_code=403, detail="cross-tenant access denied (self only)")
        return claims

    return _dep


async def _resolve_admin(request: Request, x_tenant_id: str, authorization: str) -> dict[str, Any]:
    if not x_tenant_id:
        raise HTTPException(status_code=401, detail="missing X-Tenant-Id")
    if not authorization:
        raise HTTPException(status_code=401, detail="missing token")
    svc = get_auth_service(request)
    claims = await svc.resolve_bearer_claims(authorization)
    if claims["tid"] != x_tenant_id:
        raise HTTPException(status_code=403, detail="cross-tenant access denied")
    if claims["role"] != "tenant_admin":
        raise HTTPException(status_code=403, detail="tenant_admin role required")
    return claims


async def require_service_token(
    request: Request,
    authorization: str = Header(default=""),
) -> None:
    settings = get_settings(request)
    if not authorization:
        raise HTTPException(status_code=401, detail="missing token")
    token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="invalid bearer token")
    if not hmac.compare_digest(token, settings.service_token):
        logger.warning("require_service_token: mismatch (fail-closed)")
        raise HTTPException(status_code=401, detail="invalid service token")


async def require_bearer(
    request: Request, authorization: str = Header(default="")
) -> dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing token")
    svc = get_auth_service(request)
    return await svc.resolve_bearer_claims(authorization)
