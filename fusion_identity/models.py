from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1)


class VerifyResponse(BaseModel):
    tid: str
    role: str
    scopes: list[str]
    quota: dict[str, Any]
    revoked: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class RevokeRequest(BaseModel):
    jti: str = Field(min_length=1)


class TenantCreate(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1)
    plan: str = Field(default="team")


class TenantUpdate(BaseModel):
    display_name: str | None = None
    status: str | None = None
    plan: str | None = None


class MemberAdd(BaseModel):
    user_id: str = Field(min_length=1)
    role: str = Field(min_length=1)


class MemberCreate(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    email: str | None = None
    role: str = Field(min_length=1)


class ApiKeyCreate(BaseModel):
    scopes: list[str] = Field(default_factory=list)


class ApiKeyResponse(BaseModel):
    key_id: str
    raw_key: str
    prefix: str
    scopes: list[str]


class QuotaUpdate(BaseModel):
    rpm: int | None = None
    tpm: int | None = None
    concurrent: int | None = None
    storage_mb: int | None = None
    allowed_models: list[str] | None = None
