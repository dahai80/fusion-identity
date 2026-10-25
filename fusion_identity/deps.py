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


require_tenant_admin.__fusion_guard__ = ("*", "admin")


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

    _dep.__fusion_guard__ = ("*", "admin")
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


async def _role_allows(
    store: InMemoryStore,
    tenant_id: str,
    role: str,
    resource: str,
    action: str,
) -> bool:
    # Issue #16: permission-point check. tenant_admin = full; built-in roles
    # follow BUILTIN_ROLE_MATRIX; a custom role (issue #12) is granted every
    # action on a resource when its write_classes contain "{resource}:write"
    # (write implies read/delete) and nothing otherwise. Deny-by-default.
    from fusion_identity.store import BUILTIN_ROLE_MATRIX

    if role == "tenant_admin":
        return True
    if role in BUILTIN_ROLE_MATRIX:
        return action in BUILTIN_ROLE_MATRIX[role].get(resource, ())
    rec = await store.get_role(tenant_id, role)
    if rec is None:
        return False
    return f"{resource}:write" in set(rec.get("write_classes", []))


def _permission_denied(resource: str, action: str, role: str) -> HTTPException:
    logger.warning("permission denied: role=%s needs %s:%s", role, resource, action)
    return HTTPException(
        status_code=403, detail=f"{resource}:{action} not permitted for role {role}"
    )


async def _resolve_permission(
    request: Request,
    x_tenant_id: str,
    authorization: str,
    resource: str,
    action: str,
    tenant_id_param: str | None,
) -> dict[str, Any]:
    if not x_tenant_id:
        raise HTTPException(status_code=401, detail="missing X-Tenant-Id")
    if not authorization:
        raise HTTPException(status_code=401, detail="missing token")
    svc = get_auth_service(request)
    claims = await svc.resolve_bearer_claims(authorization)
    if claims["tid"] != x_tenant_id:
        raise HTTPException(status_code=403, detail="cross-tenant access denied")
    if tenant_id_param is not None:
        path_tenant = request.path_params.get(tenant_id_param)
        if path_tenant is not None and claims["tid"] != path_tenant:
            logger.warning(
                "cross-tenant blocked: token tid=%s path %s=%s",
                claims["tid"],
                tenant_id_param,
                path_tenant,
            )
            raise HTTPException(status_code=403, detail="cross-tenant access denied (self only)")
    store = get_store(request)
    if not await _role_allows(store, claims["tid"], claims["role"], resource, action):
        raise _permission_denied(resource, action, claims["role"])
    return claims


def require_permission(resource: str, action: str):
    # Issue #16: capability dependency factory — every tenant-scoped route
    # declares its (resource, action) point explicitly; nothing is implicit.
    async def _dep(
        request: Request,
        x_tenant_id: str = Header(default=""),
        authorization: str = Header(default=""),
    ) -> dict[str, Any]:
        return await _resolve_permission(
            request, x_tenant_id, authorization, resource, action, None
        )

    _dep.__fusion_guard__ = (resource, action)
    return _dep


def require_permission_of(resource: str, action: str, tenant_id_param: str = "tenant_id"):
    # Same as require_permission plus the cross-tenant path guard
    # (token tid must match BOTH X-Tenant-Id and the path {tenant_id}).
    async def _dep(
        request: Request,
        x_tenant_id: str = Header(default=""),
        authorization: str = Header(default=""),
    ) -> dict[str, Any]:
        return await _resolve_permission(
            request, x_tenant_id, authorization, resource, action, tenant_id_param
        )

    _dep.__fusion_guard__ = (resource, action)
    return _dep


async def require_service_token(
    request: Request,
    authorization: str = Header(default=""),
) -> None:
    from fusion_identity.jwt_utils import JwtError, extract_bearer

    settings = get_settings(request)
    if not authorization:
        raise HTTPException(status_code=401, detail="missing token")
    try:
        token = extract_bearer(authorization)
    except JwtError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    if not hmac.compare_digest(token, settings.service_token):
        # D3: rotation dual-window — accept the previous service token during the
        # grace window so callers can be rotated off the old token without a
        # hard cutover. Both paths are constant-time compared; a match on the
        # prev token is logged so the operator sees who is still on the old token.
        prev = getattr(settings, "service_token_prev", None)
        if prev and hmac.compare_digest(token, prev):
            logger.warning("require_service_token: accepted via PREV token (rotation grace)")
            return
        logger.warning("require_service_token: mismatch (fail-closed)")
        raise HTTPException(status_code=401, detail="invalid service token")


require_service_token.__fusion_guard__ = ("*", "service")


async def require_bearer(
    request: Request, authorization: str = Header(default="")
) -> dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing token")
    svc = get_auth_service(request)
    return await svc.resolve_bearer_claims(authorization)


require_bearer.__fusion_guard__ = ("*", "bearer")


def get_cache(request: Request):
    return getattr(request.app.state, "cache", None)


async def invalidate_tenant_cache(request: Request, tenant_id: str) -> None:
    # A5: cache invalidation is security-critical (tenant disable / quota
    # tighten). A swallowed failure lets stale lenient data authorize for up
    # to TTL. Fail-closed: propagate so the mutating route can surface the
    # error rather than silently serving stale cache.
    cache = get_cache(request)
    if cache is None:
        return
    await cache.invalidate_tenant(tenant_id)


async def invalidate_tenant_api_keys_cache(request: Request, tenant_id: str) -> None:
    # L4: quota/tenant changes must also drop the per-api-key cache blob
    # (which embeds allowed_modules/max_concurrency/daily limits) — else the
    # gRPC plane authorizes on the old lenient quota for up to 300s.
    cache = get_cache(request)
    if cache is None:
        return
    store = get_store(request)
    api_keys = await store.list_api_keys(tenant_id)
    key_hashes = [k["key_hash"] for k in api_keys if k.get("key_hash")]
    await cache.invalidate_tenant_api_keys(tenant_id, key_hashes)
    await cache.invalidate_tenant(tenant_id)
