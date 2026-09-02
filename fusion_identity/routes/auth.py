from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity.auth import AuthService
from fusion_identity.deps import get_auth_service, require_bearer, require_service_token
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

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    req: LoginRequest,
    request: Request,
    svc: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    check_login_rate(request, req.tenant_id)
    return await svc.login(req)


@router.get("/verify", response_model=VerifyResponse, dependencies=[Depends(require_service_token)])
async def verify(
    token: str,
    svc: AuthService = Depends(get_auth_service),
) -> VerifyResponse:
    return await svc.verify(VerifyRequest(token=token))


@router.post(
    "/verify", response_model=VerifyResponse, dependencies=[Depends(require_service_token)]
)
async def verify_post(
    req: VerifyRequest, svc: AuthService = Depends(get_auth_service)
) -> VerifyResponse:
    return await svc.verify(req)


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

    body: dict = {}
    ctype = (request.headers.get("content-type") or "").lower()
    if "application/x-www-form-urlencoded" in ctype:
        form = await request.form()
        token = form.get("token") or ""
    else:
        raw = (await request.body()).decode()
        try:
            body = json.loads(raw or "{}")
        except json.JSONDecodeError:
            body = {}
        token = body.get("token") or ""
    if not token:
        return {"active": False}
    return await svc.introspect(token)
