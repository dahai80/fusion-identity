from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity import metrics_collector as mc
from fusion_identity.auth import AuthService
from fusion_identity.deps import get_auth_service, require_bearer, require_service_token
from fusion_identity.jwt_utils import JwtError
from fusion_identity.models import (
    LoginRequest,
    LogoutRequest,
    PasswordChangeRequest,
    RefreshRequest,
    RevokeRequest,
    TokenResponse,
    VerifyRequest,
    VerifyResponse,
)
from fusion_identity.ratelimit import check_login_rate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    req: LoginRequest,
    request: Request,
    svc: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    await check_login_rate(request, req.tenant_id, req.username)
    try:
        resp = await svc.login(req)
        # P3-1: the auth_requests_total counter only recorded gRPC authorize
        # calls; HTTP logins were invisible to monitoring. Record here too.
        mc.record_auth(req.tenant_id, "http", "login_ok", 200)
        return resp
    except HTTPException as exc:
        mc.record_auth(req.tenant_id, "http", "login_fail", exc.status_code)
        raise


@router.get("/verify", response_model=VerifyResponse, dependencies=[Depends(require_service_token)])
async def verify(
    token: str,
    svc: AuthService = Depends(get_auth_service),
) -> VerifyResponse:
    try:
        return await svc.verify(VerifyRequest(token=token))
    except JwtError as exc:
        logger.info("verify GET: rejected token: %s", exc)
        raise HTTPException(status_code=401, detail="invalid token") from exc


@router.post(
    "/verify", response_model=VerifyResponse, dependencies=[Depends(require_service_token)]
)
async def verify_post(
    req: VerifyRequest, svc: AuthService = Depends(get_auth_service)
) -> VerifyResponse:
    try:
        return await svc.verify(req)
    except JwtError as exc:
        logger.info("verify POST: rejected token: %s", exc)
        raise HTTPException(status_code=401, detail="invalid token") from exc


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    req: RefreshRequest, svc: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    return await svc.refresh(req)


@router.post("/revoke")
async def revoke(
    req: RevokeRequest,
    claims: dict = Depends(require_bearer),
    svc: AuthService = Depends(get_auth_service),
) -> dict:
    if claims.get("role") != "tenant_admin":
        raise HTTPException(status_code=403, detail="tenant_admin role required")
    return await svc.revoke(req, claims["tid"], claims.get("sub"))


@router.post("/logout")
async def logout(
    req: LogoutRequest,
    claims: dict = Depends(require_bearer),
    svc: AuthService = Depends(get_auth_service),
) -> dict:
    return await svc.logout(claims, req.refresh_token)


@router.post("/password")
async def change_password(
    req: PasswordChangeRequest,
    claims: dict = Depends(require_bearer),
    svc: AuthService = Depends(get_auth_service),
) -> dict:
    return await svc.change_password(
        claims["sub"], req.old_password, req.new_password, tenant_id=claims["tid"]
    )


@router.post(
    "/introspect",
    dependencies=[Depends(require_service_token)],
    response_model_exclude_none=True,
)
async def introspect(
    request: Request,
    svc: AuthService = Depends(get_auth_service),
) -> dict:
    import json

    # L18: cap the raw request body up front so neither the form nor the JSON
    # branch can be forced to buffer an unbounded payload on this
    # service-token endpoint.
    raw = await request.body()
    if len(raw) > 32768:
        raise HTTPException(status_code=413, detail="introspect body too large")
    body: dict = {}
    ctype = (request.headers.get("content-type") or "").lower()
    if "application/x-www-form-urlencoded" in ctype:
        form = await request.form()
        token = form.get("token") or ""
    else:
        # decode defensively so a non-UTF-8 payload cannot crash with a 500
        text = raw.decode("utf-8", errors="replace")
        try:
            body = json.loads(text or "{}")
        except json.JSONDecodeError:
            body = {}
        token = body.get("token") or ""
    if not token:
        return {"active": False}
    return await svc.introspect(token)
