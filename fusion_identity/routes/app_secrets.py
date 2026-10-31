from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from fusion_identity.deps import get_settings, get_store, require_service_token
from fusion_identity.store import InMemoryStore, StoreConflict

logger = logging.getLogger(__name__)

# Issue #28 (AGENTS.md convention #1): business apps request any secret beyond
# their three env vars from identity. Service-token gated, cross-tenant plane
# (X-Tenant-Id: _system, like the admin plane). Raw key material is returned
# exactly once; identity persists only the sha256 hash. Rotation demotes the
# previous version to a grace window so the app can decrypt-and-re-encrypt
# before the old version expires.
router = APIRouter(
    prefix="/api/v1/apps",
    tags=["app-secrets"],
    dependencies=[Depends(require_service_token)],
)

_APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class AppSecretIssue(BaseModel):
    # Grace window for the demoted version, seconds. Defaults to the
    # FUSION_IDENTITY_SECRET_GRACE_SECONDS setting.
    grace_seconds: int | None = Field(default=None, ge=0, le=365 * 24 * 3600)


class AppSecretIssued(BaseModel):
    secret_id: str
    app_id: str
    version: int
    # Raw key material — shown exactly once, never stored in plaintext.
    secret: str
    status: str
    created_at: float
    previous_version: dict[str, Any] | None = None


class AppSecretVersion(BaseModel):
    secret_id: str
    app_id: str
    version: int
    status: str
    prefix: str
    created_at: float
    grace_until: float | None = None


def _validate_app_id(app_id: str) -> None:
    if not _APP_ID_RE.match(app_id):
        raise HTTPException(
            status_code=422,
            detail="app_id must match ^[a-z0-9][a-z0-9_-]{0,63}$",
        )


def _grace_seconds(body: AppSecretIssue | None, settings: Any) -> int:
    if body is not None and body.grace_seconds is not None:
        return body.grace_seconds
    return settings.secret_grace_seconds


async def _audit(store: InMemoryStore, action: str, app_id: str, detail: dict[str, Any]) -> None:
    try:
        await store.append_audit(
            tenant_id="_system",
            user_id=None,
            jti=None,
            role="service",
            action=action,
            resource=app_id,
            detail=detail,
        )
    except Exception:
        # The hash-chained ledger must never block a secret issuance, but the
        # failure is loud so the operator sees the audit gap.
        logger.exception("app_secrets: audit append failed for %s app=%s", action, app_id)


@router.post("/{app_id}/secrets", response_model=AppSecretIssued, status_code=201)
async def issue_app_secret(
    app_id: str,
    body: AppSecretIssue | None = None,
    store: InMemoryStore = Depends(get_store),
    settings: Any = Depends(get_settings),
) -> AppSecretIssued:
    _validate_app_id(app_id)
    current = await store.get_current_app_secret(app_id)
    if current is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"app {app_id} already has a current secret (version "
                f"{current['version']}) — use POST /secrets/rotate"
            ),
        )
    grace = _grace_seconds(body, settings)
    try:
        raw, record, prev = await store.issue_app_secret(app_id, grace)
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit(
        store,
        "app_secret.issued",
        app_id,
        {"secret_id": record["secret_id"], "version": record["version"]},
    )
    return AppSecretIssued(
        secret_id=record["secret_id"],
        app_id=app_id,
        version=record["version"],
        secret=raw,
        status=record["status"],
        created_at=record["created_at"],
        previous_version=prev,
    )


@router.get("/{app_id}/secrets", response_model=list[AppSecretVersion])
async def list_app_secrets(
    app_id: str,
    store: InMemoryStore = Depends(get_store),
) -> list[AppSecretVersion]:
    _validate_app_id(app_id)
    rows = await store.list_app_secrets(app_id)
    return [
        AppSecretVersion(
            secret_id=r["secret_id"],
            app_id=app_id,
            version=r["version"],
            status=r["status"],
            prefix=r["prefix"],
            created_at=r["created_at"],
            grace_until=r.get("grace_until"),
        )
        for r in rows
    ]


@router.post("/{app_id}/secrets/rotate", response_model=AppSecretIssued, status_code=201)
async def rotate_app_secret(
    app_id: str,
    body: AppSecretIssue | None = None,
    store: InMemoryStore = Depends(get_store),
    settings: Any = Depends(get_settings),
) -> AppSecretIssued:
    _validate_app_id(app_id)
    if not await store.has_app_secrets(app_id):
        raise HTTPException(status_code=404, detail=f"app {app_id} has no secrets to rotate")
    grace = _grace_seconds(body, settings)
    try:
        raw, record, prev = await store.issue_app_secret(app_id, grace)
    except StoreConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await _audit(
        store,
        "app_secret.rotated",
        app_id,
        {
            "secret_id": record["secret_id"],
            "version": record["version"],
            "previous_version": prev["version"] if prev else None,
        },
    )
    return AppSecretIssued(
        secret_id=record["secret_id"],
        app_id=app_id,
        version=record["version"],
        secret=raw,
        status=record["status"],
        created_at=record["created_at"],
        previous_version=prev,
    )
