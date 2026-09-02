from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity.deps import get_auth_service, require_bearer
from fusion_identity.models import MfaStatusResponse, MfaVerifyRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth/mfa", tags=["mfa"])


@router.post("/enroll")
async def enroll_mfa(
    request: Request,
    claims: dict[str, Any] = Depends(require_bearer),
) -> dict[str, Any]:
    svc = get_auth_service(request)
    uid = claims["sub"]
    res = await svc.enroll_mfa(uid)
    await request.app.state.store.append_audit(
        claims["tid"], uid, None, claims.get("role"), "mfa.enroll", "session", {"method": "totp"}
    )
    return res


@router.post("/verify", response_model=MfaStatusResponse)
async def verify_mfa(
    request: Request,
    req: MfaVerifyRequest,
    claims: dict[str, Any] = Depends(require_bearer),
) -> Any:
    svc = get_auth_service(request)
    uid = claims["sub"]
    try:
        res = await svc.verify_mfa(uid, req)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    await request.app.state.store.append_audit(
        claims["tid"],
        uid,
        None,
        claims.get("role"),
        "mfa.verify",
        "session",
        {"method": req.method},
    )
    return res


@router.get("")
async def list_mfa(
    request: Request,
    claims: dict[str, Any] = Depends(require_bearer),
) -> list[dict[str, Any]]:
    svc = get_auth_service(request)
    return await svc.list_mfa(claims["sub"])


@router.delete("/{method}")
async def delete_mfa(
    request: Request,
    method: str,
    claims: dict[str, Any] = Depends(require_bearer),
) -> dict[str, Any]:
    svc = get_auth_service(request)
    ok = await svc.delete_mfa(claims["sub"], method)
    if not ok:
        raise HTTPException(status_code=404, detail="mfa method not found")
    await request.app.state.store.append_audit(
        claims["tid"],
        claims["sub"],
        None,
        claims.get("role"),
        "mfa.delete",
        "session",
        {"method": method},
    )
    return {"deleted": True, "method": method}
