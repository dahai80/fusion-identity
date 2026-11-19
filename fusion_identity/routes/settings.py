from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from fusion_identity.deps import get_store, require_bearer
from fusion_identity.ops_events import emit_data_reflow_optout, get_emitter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["settings"])


class UserSettingsResponse(BaseModel):
    data_reflow_enabled: bool


class UserSettingsUpdate(BaseModel):
    data_reflow_enabled: bool


@router.get("/settings", response_model=UserSettingsResponse)
async def get_user_settings(
    claims: dict = Depends(require_bearer),
    store: Any = Depends(get_store),
) -> UserSettingsResponse:
    # Issue #101: self-service privacy surface — per-user data-reflow
    # opt-out. User-scoped (tenant-middleware-exempt; bearer enforced here).
    enabled = await store.data_reflow_enabled(claims["sub"])
    return UserSettingsResponse(data_reflow_enabled=enabled)


@router.put("/settings", response_model=UserSettingsResponse)
async def update_user_settings(
    req: UserSettingsUpdate,
    request: Request,
    claims: dict = Depends(require_bearer),
    store: Any = Depends(get_store),
) -> UserSettingsResponse:
    enabled = bool(req.data_reflow_enabled)
    ok = await store.set_data_reflow_enabled(claims["sub"], enabled)
    if not ok:
        logger.warning("update_settings: unknown user sub=%s", claims["sub"])
        raise HTTPException(status_code=404, detail="user not found")
    # true→false transition: tell the ops pipeline so stored samples for this
    # user can be purged/anonymized per retention policy (issue #101).
    if not enabled:
        await emit_data_reflow_optout(get_emitter(request.app.state), claims["tid"], claims["sub"])
    try:
        await store.append_audit(
            tenant_id=claims["tid"],
            user_id=claims["sub"],
            jti=None,
            role=claims.get("role", "member"),
            action="auth.settings_updated",
            resource=None,
            detail={"data_reflow_enabled": enabled},
        )
    except Exception:
        logger.exception("update_settings: audit append failed sub=%s", claims["sub"])
    logger.info("update_settings: sub=%s data_reflow_enabled=%s", claims["sub"], enabled)
    return UserSettingsResponse(data_reflow_enabled=enabled)
