from __future__ import annotations

import re
import time
from typing import Any

from pydantic import BaseModel, Field, field_validator

VALID_ROLES = ("tenant_admin", "operator", "member", "viewer")
VALID_USER_STATUS = ("active", "disabled", "locked")


def _validate_password(v: str) -> str:
    if len(v) < 10:
        raise ValueError("password must be at least 10 characters")
    if not re.search(r"[A-Za-z]", v):
        raise ValueError("password must contain at least one letter")
    if not re.search(r"\d", v):
        raise ValueError("password must contain at least one digit")
    return v


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    mfa_code: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    must_change_password: bool = False
    mfa_required: bool = False


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1)


class VerifyResponse(BaseModel):
    tid: str
    role: str
    scopes: list[str]
    quota: dict[str, Any]
    tenant_status: str = "active"
    revoked: bool = False
    write_classes: list[str] = Field(default_factory=list)
    allowed_menus: list[str] = Field(default_factory=list)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class RevokeRequest(BaseModel):
    jti: str = Field(min_length=1)


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class PasswordChangeRequest(BaseModel):
    old_password: str = Field(min_length=1)
    new_password: str = Field(min_length=1)

    @field_validator("new_password")
    @classmethod
    def _check_new(cls, v: str) -> str:
        return _validate_password(v)


class PasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=1)

    @field_validator("new_password")
    @classmethod
    def _check_new(cls, v: str) -> str:
        return _validate_password(v)


class TenantCreate(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1)
    plan: str = Field(default="team")


class TenantUpdate(BaseModel):
    display_name: str | None = None
    status: str | None = None
    plan: str | None = None

    @field_validator("status")
    @classmethod
    def _check_status(cls, v: str | None) -> str | None:
        if v is not None and v not in ("active", "disabled"):
            raise ValueError("status must be active or disabled (hard delete is platform-only)")
        return v


class MemberAdd(BaseModel):
    # Issue #12: role validation moved to the store layer — a role id may be
    # built-in or a per-tenant custom role, so static enum checks fail-open
    # nothing; the store is the single fail-closed authority.
    user_id: str = Field(min_length=1)
    role: str = Field(min_length=1, max_length=64)


class MemberCreate(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    email: str | None = None
    role: str = Field(min_length=1, max_length=64)

    @field_validator("password")
    @classmethod
    def _check_pw(cls, v: str) -> str:
        return _validate_password(v)


class MemberRoleUpdate(BaseModel):
    role: str = Field(min_length=1, max_length=64)


class MemberStatusUpdate(BaseModel):
    status: str = Field(min_length=1)

    @field_validator("status")
    @classmethod
    def _check_status(cls, v: str) -> str:
        if v not in VALID_USER_STATUS:
            raise ValueError(f"status must be one of {VALID_USER_STATUS}")
        return v


class ApiKeyCreate(BaseModel):
    scopes: list[str] = Field(default_factory=list)


class ApiKeyResponse(BaseModel):
    key_id: str
    raw_key: str
    prefix: str
    scopes: list[str]
    user_id: str | None = None


class QuotaUpdate(BaseModel):
    rpm: int | None = None
    tpm: int | None = None
    concurrent: int | None = None
    storage_mb: int | None = None
    allowed_models: list[str] | None = None
    allowed_modules: list[str] | None = None
    default_priority: int | None = None


class UsageEmit(BaseModel):
    metric: str = Field(min_length=1)
    value: int = Field(ge=0)
    source: str = Field(min_length=1)
    model: str | None = None
    user_id: str | None = None


class UsageRecord(BaseModel):
    metric: str
    value: int


class TenantConfigResponse(BaseModel):
    tenant_id: str
    display_name: str
    plan: str
    status: str
    quota: dict[str, Any]


class IdpCreate(BaseModel):
    idp_id: str
    type: str = "oidc"
    issuer_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: str | None = "openid profile email"
    auto_provision: bool = False


class IdpResponse(BaseModel):
    idp_id: str
    tenant_id: str
    type: str
    issuer_url: str | None = None
    client_id: str | None = None
    scopes: str | None = None
    auto_provision: bool
    created_at: float | None = None


class IdpUpdate(BaseModel):
    type: str | None = None
    issuer_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: str | None = None
    auto_provision: bool | None = None


class OidcCallbackRequest(BaseModel):
    code: str
    state: str | None = None
    tenant_id: str | None = None


class ScimUser(BaseModel):
    userName: str
    displayName: str | None = None
    active: bool = True
    emails: list[dict[str, Any]] | None = None


class ScimUserResponse(BaseModel):
    id: str
    userName: str
    displayName: str | None = None
    active: bool
    tenant_id: str


class MfaVerifyRequest(BaseModel):
    code: str
    method: str = "totp"


class MfaStatusResponse(BaseModel):
    method: str
    enabled: bool
    enrolled_at: float | None = None


class SessionIssueRequest(BaseModel):
    sub: str = Field(default="web-shell", min_length=1, max_length=128)
    tenant_id: str = Field(default="local", min_length=1, max_length=64)
    role: str = Field(default="member", min_length=1, max_length=64)
    ttl_seconds: int | None = Field(default=None, ge=60, le=86400)


class SessionVerifyRequest(BaseModel):
    token: str = Field(min_length=1)


class DepartmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    parent_id: str | None = Field(default=None, max_length=64)
    tool_allowlist: list[str] = Field(default_factory=list)


class DepartmentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    parent_id: str | None = Field(default=None, max_length=64)
    tool_allowlist: list[str] | None = None


class AuditEventIn(BaseModel):
    action: str = Field(min_length=1, max_length=128)
    resource: str | None = Field(default=None, max_length=256)
    user_id: str | None = Field(default=None, max_length=64)
    severity: str = Field(default="INFO")
    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: str) -> str:
        if v.upper() not in ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"):
            raise ValueError("severity must be a standard level (TRACE..FATAL)")
        return v.upper()


class BusinessAuditEventIn(BaseModel):
    # Issue #18: business-app audit events (ai-speech-exam G7) — schema-flexible
    # payload with required fields actor/action/object_id/trace_id/timestamp.
    actor: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    object_id: str = Field(min_length=1, max_length=256)
    trace_id: str = Field(min_length=1, max_length=128)
    timestamp: float
    severity: str = Field(default="INFO")
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: str) -> str:
        if v.upper() not in ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"):
            raise ValueError("severity must be a standard level (TRACE..FATAL)")
        return v.upper()

    @field_validator("timestamp")
    @classmethod
    def _check_timestamp(cls, v: float) -> float:
        now = time.time()
        if v <= 0 or v > now + 300:
            raise ValueError("timestamp must be a unix epoch within 5 minutes of now")
        return v


class RoleCreate(BaseModel):
    # Issue #12 (E5): custom role granting write classes for capability-spine
    # mutation gating. role_id validation (pattern, built-in collision) is in
    # the store layer.
    role_id: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    write_classes: list[str] = Field(default_factory=list, max_length=64)


class RoleUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    write_classes: list[str] | None = Field(default=None, max_length=64)


class RoleMenusUpdate(BaseModel):
    menus: list[str] = Field(default_factory=list, max_length=64)


class MenusAddRequest(BaseModel):
    menus: list[str] = Field(min_length=1, max_length=256)


class ApprovalValidateRequest(BaseModel):
    requester_id: str = Field(min_length=1)
    approver_id: str = Field(min_length=1)
