from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from fusion_identity.crypto import CryptoError, decrypt_secret, encrypt_secret
from fusion_identity.deps import get_settings, get_store, require_service_token
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

# Issue #34 (ai-trysuite §8.2 / AGENTS.md convention #1): business-app provider
# layers consume third-party SaaS API keys through identity. Unlike app_secrets
# (issue #28), these values are EXTERNALLY issued — identity cannot rotate them
# into existence — so they are stored AES-256-GCM encrypted under the KEK and
# must be recoverable by the consumer: boot injection pulls the current value at
# startup; a SaaS 401/403 triggers one re-pull + one retry (app-side debounce).
# Service-token gated, cross-tenant plane (X-Tenant-Id: _system).
router = APIRouter(
    prefix="/api/v1/apps",
    tags=["app-credentials"],
    dependencies=[Depends(require_service_token)],
)

_APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_CRED_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


class AppCredentialPut(BaseModel):
    # Raw SaaS-issued credential material. Encrypted at rest under the KEK;
    # never stored in plaintext, never logged.
    value: str = Field(min_length=1, max_length=8192)


class AppCredentialMeta(BaseModel):
    app_id: str
    name: str
    created_at: float
    updated_at: float
    fetch_count: int
    last_fetched_at: float | None = None


class AppCredentialFetched(BaseModel):
    app_id: str
    name: str
    value: str
    created_at: float
    updated_at: float
    fetch_count: int
    last_fetched_at: float | None = None


def _validate_ids(app_id: str, name: str) -> None:
    if not _APP_ID_RE.match(app_id):
        raise HTTPException(
            status_code=422,
            detail="app_id must match ^[a-z0-9][a-z0-9_-]{0,63}$",
        )
    if not _CRED_NAME_RE.match(name):
        raise HTTPException(
            status_code=422,
            detail="credential name must match ^[a-z0-9][a-z0-9_.-]{0,63}$",
        )


async def _audit(store: InMemoryStore, action: str, app_id: str, name: str) -> None:
    try:
        await store.append_audit(
            tenant_id="_system",
            user_id=None,
            jti=None,
            role="service",
            action=action,
            resource=f"{app_id}/{name}",
            detail={"app_id": app_id, "name": name},
        )
    except Exception:
        # The hash-chained ledger must never block a credential operation, but
        # the failure is loud so the operator sees the audit gap.
        logger.exception(
            "app_credentials: audit append failed for %s app=%s name=%s",
            action,
            app_id,
            name,
        )


@router.put("/{app_id}/credentials/{name}", response_model=AppCredentialMeta)
async def put_app_credential(
    app_id: str,
    name: str,
    body: AppCredentialPut,
    store: InMemoryStore = Depends(get_store),
    settings: Any = Depends(get_settings),
) -> AppCredentialMeta:
    _validate_ids(app_id, name)
    enc = encrypt_secret(body.value, settings.kek)
    rec = await store.put_app_credential(app_id, name, enc)
    await _audit(store, "app_credential.stored", app_id, name)
    return AppCredentialMeta(
        app_id=rec["app_id"],
        name=rec["name"],
        created_at=rec["created_at"],
        updated_at=rec["updated_at"],
        fetch_count=rec["fetch_count"],
        last_fetched_at=rec.get("last_fetched_at"),
    )


@router.get("/{app_id}/credentials/{name}", response_model=AppCredentialFetched)
async def get_app_credential(
    app_id: str,
    name: str,
    store: InMemoryStore = Depends(get_store),
    settings: Any = Depends(get_settings),
) -> AppCredentialFetched:
    _validate_ids(app_id, name)
    rec = await store.get_app_credential(app_id, name)
    if rec is None:
        raise HTTPException(
            status_code=404,
            detail=f"credential {name} not found for app {app_id}",
        )
    try:
        value = decrypt_secret(rec["secret_enc"], settings.kek, settings.kek_prev)
    except CryptoError as exc:
        # Fail visibly, never leak a partial value — a wrong/tampered blob is an
        # operational incident (KEK mismatch or DB corruption), not a 404.
        logger.error("get_app_credential: decrypt failed app=%s name=%s", app_id, name)
        raise HTTPException(
            status_code=500,
            detail="credential decryption failed (KEK mismatch or corrupt blob)",
        ) from exc
    await _audit(store, "app_credential.fetched", app_id, name)
    return AppCredentialFetched(
        app_id=rec["app_id"],
        name=rec["name"],
        value=value,
        created_at=rec["created_at"],
        updated_at=rec["updated_at"],
        fetch_count=rec["fetch_count"],
        last_fetched_at=rec.get("last_fetched_at"),
    )
