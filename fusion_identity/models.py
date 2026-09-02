from __future__ import annotations

import re
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
    user_id: str = Field(min_length=1)
    role: str = Field(min_length=1)

    @field_validator("role")
    @classmethod
    def _check_role(cls, v: str) -> str:
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        return v


class MemberCreate(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    email: str | None = None
    role: str = Field(min_length=1)

    @field_validator("role")
    @classmethod
    def _check_role(cls, v: str) -> str:
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        return v

    @field_validator("password")
    @classmethod
    def _check_pw(cls, v: str) -> str:
        return _validate_password(v)


class MemberRoleUpdate(BaseModel):
    role: str = Field(min_length=1)

    @field_validator("role")
    @classmethod
    def _check_role(cls, v: str) -> str:
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        return v


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
