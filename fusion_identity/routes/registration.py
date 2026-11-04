from __future__ import annotations

import hashlib
import logging
import re
import secrets
import time
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from fusion_identity.auth import AuthService
from fusion_identity.deps import get_auth_service, get_settings, get_store
from fusion_identity.email_sender import EmailDeliveryError, send_verification_email
from fusion_identity.models import LoginRequest, _validate_password
from fusion_identity.ratelimit import check_login_rate
from fusion_identity.routes.provisioning import ApiKeySpec, SeedAdminSpec, provision_core
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

# Issue #39 (fusion-site-auth-1104 §2-§3): public registration channels A
# (personal) + B (tenant). Both are thin wrappers over the EXISTING creation
# internals — create_user for channel A, provision_core for channel B — so
# there is no second user/tenant creation code path. Both are rate-limited
# (identity-side; gateway edge limits are a gateway concern) and audited.
router = APIRouter(prefix="/api/v1/auth", tags=["registration"])

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=10, max_length=256)
    display_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=254)

    @field_validator("username")
    @classmethod
    def _check_username(cls, v: str) -> str:
        if not _USERNAME_RE.match(v):
            raise ValueError("username must match ^[a-zA-Z0-9_.-]{3,64}$")
        return v

    @field_validator("password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        return _validate_password(v)


class RegisterTenantRequest(BaseModel):
    tenant_display_name: str = Field(min_length=1, max_length=128)
    admin_username: str = Field(min_length=3, max_length=64)
    # 12-char floor matches SeedAdminSpec (shared provision path) — stricter
    # than the 10-char _validate_password base on purpose: tenant admins hold
    # more power than personal users.
    admin_password: str = Field(min_length=12, max_length=256)
    admin_email: str | None = Field(default=None, max_length=254)
    plan: str = Field(default="free", max_length=32)

    @field_validator("admin_username")
    @classmethod
    def _check_username(cls, v: str) -> str:
        if not _USERNAME_RE.match(v):
            raise ValueError("admin_username must match ^[a-zA-Z0-9_.-]{3,64}$")
        return v

    @field_validator("admin_password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        return _validate_password(v)


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=16, max_length=256)


class ResendVerificationRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _mask_email(email: str) -> str:
    name, _, domain = email.partition("@")
    if not domain:
        return "***"
    shown = name[:2] if len(name) > 2 else name[:1]
    return f"{shown}***@{domain}"


async def _audit(store: InMemoryStore, action: str, user_id: str | None, detail: dict) -> None:
    try:
        await store.append_audit(
            tenant_id="_system",
            user_id=user_id,
            jti=None,
            role="public",
            action=action,
            resource=None,
            detail=detail,
        )
    except Exception:
        logger.exception("registration: audit append failed for %s", action)


async def _issue_verify_token(
    store: InMemoryStore, settings: Any, user_id: str, email: str, username: str
) -> str:
    # Issue #39: mint a single-use expiring verification token, store the hash,
    # deliver the raw token out-of-band. Never returned in an API response.
    token = secrets.token_urlsafe(32)
    ok = await store.set_email_verify_token(
        user_id, _hash_token(token), time.time() + settings.email_verify_ttl_seconds
    )
    if not ok:
        raise HTTPException(status_code=500, detail="failed to arm verification token")
    try:
        await send_verification_email(settings, email, token, username)
    except EmailDeliveryError:
        # Signup itself must not fail because SMTP hiccuped — the resend
        # endpoint covers delivery retries.
        logger.warning("registration: verification email delivery failed user=%s", user_id)
    return token


@router.post("/register", status_code=201)
async def register(
    body: RegisterRequest,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    settings: Any = Depends(get_settings),
    svc: AuthService = Depends(get_auth_service),
) -> dict[str, Any]:
    # Channel A: personal signup. The user is created globally; membership in
    # the default join tenant (community, open policy per design decision 2)
    # is what makes the returned token pair a REAL tenant token — without it a
    # membership-less user could never mint one (login requires membership).
    if not settings.registration_enabled:
        logger.warning("register: rejected — public registration disabled")
        raise HTTPException(status_code=403, detail="public registration is disabled")
    await check_login_rate(request, "register", body.username)
    email = (body.email or "").strip() or None
    if settings.email_verification_required and not email:
        raise HTTPException(
            status_code=422,
            detail="email is required while email verification is enforced",
        )
    if await store.get_user_by_username(body.username) is not None:
        raise HTTPException(status_code=409, detail="username already exists")

    user_id = "usr_" + secrets.token_hex(6)
    verified_now = not settings.email_verification_required
    user = await store.create_user(
        user_id,
        body.username,
        body.password,
        email=email,
        display_name=body.display_name,
        email_verified=verified_now,
    )

    tenant_id = settings.registration_default_tenant
    if await store.get_tenant_status(tenant_id) is None:
        # Auto-create the default join tenant (free plan, decision 2) on
        # first personal signup.
        template = await store.get_plan_template("free")
        await store.create_tenant(tenant_id, display_name="Community", plan="free")
        if template is not None:
            await store.put_quota(tenant_id, **template)
        logger.info("register: auto-created default join tenant=%s", tenant_id)
    await store.add_member(tenant_id, user_id, "member", added_by="registration")

    tokens_out: dict[str, Any] | None = None
    if verified_now:
        tokens_out = dict(
            await svc.login(
                LoginRequest(username=body.username, password=body.password, tenant_id=tenant_id)
            )
        )
    else:
        await _issue_verify_token(store, settings, user_id, email, body.username)

    await _audit(
        store,
        "auth.registered",
        user_id,
        {
            "username": body.username,
            "tenant_id": tenant_id,
            "email": _mask_email(email) if email else None,
            "verification": "verified" if verified_now else "pending",
        },
    )
    logger.info(
        "register: user=%s tenant=%s verification=%s",
        user_id,
        tenant_id,
        "verified" if verified_now else "pending",
    )
    resp: dict[str, Any] = {
        "user_id": user["user_id"],
        "username": user["username"],
        "tenant_id": tenant_id,
        "email_verified": verified_now,
    }
    if tokens_out is not None:
        resp["tokens"] = tokens_out
    else:
        resp["status"] = "verification_required"
        resp["message"] = "check your inbox for the verification link, then log in"
    return resp


@router.post("/register-tenant", status_code=201)
async def register_tenant(
    body: RegisterTenantRequest,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    settings: Any = Depends(get_settings),
    svc: AuthService = Depends(get_auth_service),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    # Channel B: tenant signup — a thin PUBLIC wrapper over the same
    # provision_core the admin route uses (tenant + plan-quota template +
    # seed admin; auto-active per locked design decision 1). No api_key, no
    # hook: those remain admin-plane capabilities.
    if not settings.registration_enabled:
        logger.warning("register_tenant: rejected — public registration disabled")
        raise HTTPException(status_code=403, detail="public registration is disabled")
    await check_login_rate(request, "register-tenant", body.admin_username)
    email = (body.admin_email or "").strip() or None
    if settings.email_verification_required and not email:
        raise HTTPException(
            status_code=422,
            detail="admin_email is required while email verification is enforced",
        )
    if await store.get_plan_template(body.plan) is None:
        raise HTTPException(status_code=422, detail=f"unknown plan {body.plan!r}")

    result = await provision_core(
        store,
        settings,
        request,
        tenant_id=None,
        display_name=body.tenant_display_name,
        plan=body.plan,
        quotas=None,
        seed_admin=SeedAdminSpec(
            username=body.admin_username,
            password=body.admin_password,
            email=email,
            email_verified=not settings.email_verification_required,
        ),
        api_key=ApiKeySpec(),
        hook_url=None,
        endpoint="/api/v1/auth/register-tenant",
        idempotency_key=idempotency_key,
        added_by="registration",
    )

    tenant_id = result["tenant"]["tenant_id"]
    # The seed admin's password was user-chosen — never echo it back.
    if result.get("admin") is not None:
        result["admin"].pop("initial_password", None)

    if settings.email_verification_required and email and result.get("admin") is not None:
        await _issue_verify_token(
            store, settings, result["admin"]["user_id"], email, body.admin_username
        )

    # Issue #39: the signup request itself presented the credentials, so this
    # one issuance bypasses the verification gate (later logins stay gated).
    tokens = dict(
        await svc.login(
            LoginRequest(
                username=body.admin_username, password=body.admin_password, tenant_id=tenant_id
            ),
            skip_email_verification=True,
        )
    )
    await _audit(
        store,
        "auth.tenant_registered",
        result["admin"]["user_id"] if result.get("admin") else None,
        {
            "tenant_id": tenant_id,
            "plan": body.plan,
            "admin_username": body.admin_username,
        },
    )
    logger.info(
        "register_tenant: tenant=%s plan=%s admin=%s",
        tenant_id,
        body.plan,
        body.admin_username,
    )
    result["tokens"] = tokens
    return result


@router.post("/verify-email")
async def verify_email(
    body: VerifyEmailRequest,
    store: InMemoryStore = Depends(get_store),
) -> dict[str, Any]:
    # Issue #39: single-use, expiring token redemption. Lookup is by token
    # hash; a bad or replayed token is indistinguishable from an expired one
    # (no enumeration).
    user_id = await store.verify_email_token(_hash_token(body.token))
    if user_id is None:
        logger.warning("verify_email: invalid or expired or replayed token")
        raise HTTPException(status_code=400, detail="invalid or expired verification token")
    await _audit(store, "auth.email_verified", user_id, {})
    logger.info("verify_email: verified user=%s", user_id)
    return {"verified": True, "user_id": user_id}


@router.post("/verify-email/resend")
async def resend_verification(
    body: ResendVerificationRequest,
    request: Request,
    store: InMemoryStore = Depends(get_store),
    settings: Any = Depends(get_settings),
) -> dict[str, Any]:
    # Issue #39: PUBLIC resend (an unverified user holds no bearer token — a
    # bearer-gated resend would deadlock). Response is uniform regardless of
    # account existence/state so the endpoint cannot enumerate usernames.
    await check_login_rate(request, "verify-resend", body.username)
    user = await store.get_user_by_username(body.username)
    resent = False
    if (
        user is not None
        and not user.get("email_verified", True)
        and user.get("email")
        and settings.registration_enabled
    ):
        await _issue_verify_token(store, settings, user["user_id"], user["email"], user["username"])
        resent = True
    logger.info("resend_verification: username=%s resent=%s", body.username, resent)
    return {"resent": resent}
