from __future__ import annotations

from fastapi import APIRouter, Depends

from fusion_identity.auth import AuthService
from fusion_identity.deps import get_auth_service, require_bearer, require_service_token
from fusion_identity.models import (
    LoginRequest,
    RefreshRequest,
    RevokeRequest,
    TokenResponse,
    VerifyRequest,
    VerifyResponse,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, svc: AuthService = Depends(get_auth_service)) -> TokenResponse:
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
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail="tenant_admin role required")
    return await svc.revoke(req)
