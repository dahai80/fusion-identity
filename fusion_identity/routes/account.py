from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from fusion_identity.auth import AuthService, run_kdf, verify_password
from fusion_identity.deps import get_auth_service, get_settings, get_store, require_bearer

logger = logging.getLogger(__name__)

# Issue #91: self-service account lifecycle — deletion with a grace window
# (cancel any time before the purge deadline) and a JSON data export.
# Tenant-middleware-EXEMPT (see app.py): these are user-scoped, not
# tenant-scoped, so a multi-tenant user needs no X-Tenant-Id here; auth is
# enforced by require_bearer + a password re-confirm on delete.

router = APIRouter(prefix="/api/v1/auth/account", tags=["account"])


class AccountDeleteRequest(BaseModel):
    # Password re-confirm — the bearer alone must not be able to destroy the
    # account (a stolen token gets a grace window to notice, not a wipe).
    password: str = Field(min_length=10, max_length=256)


async def _audit(store: Any, action: str, user_id: str | None, detail: dict) -> None:
    try:
        await store.append_audit(
            tenant_id="_system",
            user_id=user_id,
            jti=None,
            role="public" if user_id else "deleted",
            action=action,
            resource=None,
            detail=detail,
        )
    except Exception:
        logger.exception("account: audit append failed for %s", action)


@router.post("/delete")
async def delete_account(
    body: AccountDeleteRequest,
    request: Request,
    claims: dict[str, Any] = Depends(require_bearer),
    store: Any = Depends(get_store),
    settings: Any = Depends(get_settings),
    svc: AuthService = Depends(get_auth_service),
) -> dict[str, Any]:
    user = await store.get_user(claims["sub"])
    if user is None:
        raise HTTPException(status_code=401, detail="account not found")
    ok, _ = await run_kdf(
        verify_password,
        body.password,
        password_hash_v=user.get("password_hash_v", ""),
        password_hash=user.get("password_hash", ""),
        salt=user.get("salt", ""),
        algo=user.get("password_algo", "argon2id"),
    )
    if not ok:
        logger.warning("delete_account: password re-confirm failed user=%s", claims["sub"])
        raise HTTPException(status_code=401, detail="password confirmation failed")
    purge_at = time.time() + settings.delete_grace_seconds
    row = await store.request_account_deletion(claims["sub"], purge_at)
    # Bearer + refresh planes die immediately; the users row survives until
    # purge_at so the cancel endpoint can restore access.
    revoked = await store.revoke_user_sessions(claims["sub"])
    await _audit(
        store,
        "account.delete_requested",
        claims["sub"],
        {"purge_at": purge_at, "grace_seconds": settings.delete_grace_seconds},
    )
    logger.info("delete_account: user=%s purge_at=%s revoked=%s", claims["sub"], purge_at, revoked)
    return {
        "scheduled": True,
        "purge_at": row["purge_at"],
        "grace_seconds": settings.delete_grace_seconds,
        "cancel_until": row["purge_at"],
    }


@router.delete("/delete")
async def cancel_account_deletion(
    request: Request,
    claims: dict[str, Any] = Depends(require_bearer),
    store: Any = Depends(get_store),
) -> dict[str, Any]:
    cancelled = await store.cancel_account_deletion(claims["sub"])
    if not cancelled:
        raise HTTPException(status_code=404, detail="no pending account deletion")
    await _audit(store, "account.delete_cancelled", claims["sub"], {})
    logger.info("cancel_account_deletion: user=%s", claims["sub"])
    return {"cancelled": True}


@router.get("/export")
async def export_account(
    request: Request,
    claims: dict[str, Any] = Depends(require_bearer),
    store: Any = Depends(get_store),
) -> dict[str, Any]:
    # Issue #91: JSON export — profile + memberships + the user's own audit
    # trail. Session secrets, password hashes, and other tenants' data never
    # leave the service.
    user = await store.get_user(claims["sub"])
    if user is None:
        raise HTTPException(status_code=401, detail="account not found")
    profile = {
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user.get("email"),
        "display_name": user.get("display_name"),
        "status": user.get("status"),
        "email_verified": user.get("email_verified", True),
        "created_at": user.get("created_at"),
        "last_login_at": user.get("last_login_at"),
    }
    memberships = [
        {"tenant_id": m["tenant_id"], "role": m["role"]}
        for m in await store.memberships_for_user(claims["sub"])
    ]
    audit = await store.audit_for_user(claims["sub"], limit=500)
    logger.info(
        "export_account: user=%s memberships=%d audit=%d",
        claims["sub"],
        len(memberships),
        len(audit),
    )
    return {"profile": profile, "memberships": memberships, "audit": audit}
