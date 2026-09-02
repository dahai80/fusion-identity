from __future__ import annotations

import contextlib
import logging
from typing import Any, Protocol

from fusion_identity.jwt_utils import issue_token, verify_token
from fusion_identity.models import (
    LoginRequest,
    RefreshRequest,
    RevokeRequest,
    TokenResponse,
    VerifyRequest,
    VerifyResponse,
)
from fusion_identity.store import InMemoryStore, StoreConflict, verify_password

logger = logging.getLogger(__name__)


class StoreProto(Protocol):
    async def get_user_by_username(self, username: str) -> dict[str, Any] | None: ...
    async def get_member_role(self, tenant_id: str, user_id: str) -> str | None: ...
    async def get_quota(self, tenant_id: str) -> dict[str, Any] | None: ...
    async def is_jti_revoked(self, jti: str) -> bool: ...
    async def revoke_jti(self, jti: str) -> None: ...
    async def append_audit(
        self,
        tenant_id: str,
        user_id: str | None,
        jti: str | None,
        role: str | None,
        action: str,
        resource: str | None,
        detail: Any,
    ) -> dict[str, Any]: ...


class AuthService:
    def __init__(
        self,
        store: StoreProto,
        *,
        signing_key: str,
        issuer: str,
        audience: str,
        ttl: int,
        refresh_ttl: int,
    ) -> None:
        self._store = store
        self._signing_key = signing_key
        self._issuer = issuer
        self._audience = audience
        self._ttl = ttl
        self._refresh_ttl = refresh_ttl

    async def login(self, req: LoginRequest) -> TokenResponse:
        user = await self._store.get_user_by_username(req.username)
        if user is None:
            logger.warning("login: unknown username=%s tid=%s", req.username, req.tenant_id)
            raise _unauthorized("invalid credentials")
        if not verify_password(req.password, user["password_hash"]):
            logger.warning("login: bad password username=%s tid=%s", req.username, req.tenant_id)
            raise _unauthorized("invalid credentials")
        role = await self._store.get_member_role(req.tenant_id, user["user_id"])
        if role is None:
            logger.warning("login: user=%s not member of tenant=%s", user["user_id"], req.tenant_id)
            raise _unauthorized("not a member of tenant")
        scopes = _role_scopes(role)
        access, jti = issue_token(
            sub=user["user_id"],
            tid=req.tenant_id,
            role=role,
            scopes=scopes,
            signing_key=self._signing_key,
            issuer=self._issuer,
            audience=self._audience,
            ttl_seconds=self._ttl,
            token_type="access",
        )
        refresh, _ = issue_token(
            sub=user["user_id"],
            tid=req.tenant_id,
            role=role,
            scopes=scopes,
            signing_key=self._signing_key,
            issuer=self._issuer,
            audience=self._audience,
            ttl_seconds=self._refresh_ttl,
            token_type="refresh",
        )
        await self._store.append_audit(
            req.tenant_id,
            user["user_id"],
            jti,
            role,
            "auth.login",
            "session",
            {"username": req.username},
        )
        return TokenResponse(access_token=access, refresh_token=refresh, expires_in=self._ttl)

    async def verify(self, req: VerifyRequest) -> VerifyResponse:
        claims = verify_token(
            req.token, self._signing_key, self._issuer, self._audience, token_type="access"
        )
        jti = claims["jti"]
        if await self._store.is_jti_revoked(jti):
            logger.warning("verify: revoked jti=%s", jti)
            raise _unauthorized("revoked token")
        role = await self._store.get_member_role(claims["tid"], claims["sub"])
        if role is None:
            logger.warning("verify: membership gone sub=%s tid=%s", claims["sub"], claims["tid"])
            raise _unauthorized("membership revoked")
        if role != claims.get("role"):
            logger.warning(
                "verify: role drift token=%s db=%s sub=%s", claims.get("role"), role, claims["sub"]
            )
            claims["role"] = role
            claims["scope"] = _role_scopes(role)
        quota = await self._store.get_quota(claims["tid"]) or {}
        return VerifyResponse(
            tid=claims["tid"], role=role, scopes=list(claims.get("scope", [])), quota=quota
        )

    async def refresh(self, req: RefreshRequest) -> TokenResponse:
        claims = verify_token(
            req.refresh_token, self._signing_key, self._issuer, self._audience, token_type="refresh"
        )
        if await self._store.is_jti_revoked(claims["jti"]):
            raise _unauthorized("revoked refresh token")
        role = await self._store.get_member_role(claims["tid"], claims["sub"])
        if role is None:
            raise _unauthorized("membership revoked")
        scopes = _role_scopes(role)
        access, jti = issue_token(
            sub=claims["sub"],
            tid=claims["tid"],
            role=role,
            scopes=scopes,
            signing_key=self._signing_key,
            issuer=self._issuer,
            audience=self._audience,
            ttl_seconds=self._ttl,
            token_type="access",
        )
        await self._store.append_audit(
            claims["tid"], claims["sub"], jti, role, "auth.refresh", "session", {}
        )
        return TokenResponse(
            access_token=access, refresh_token=req.refresh_token, expires_in=self._ttl
        )

    async def revoke(self, req: RevokeRequest) -> dict[str, Any]:
        await self._store.revoke_jti(req.jti)
        await self._store.append_audit(
            "system", None, req.jti, None, "auth.revoke", "session", {"jti": req.jti}
        )
        return {"revoked": True, "jti": req.jti}

    async def resolve_bearer_claims(self, auth_header: str) -> dict[str, Any]:
        from fusion_identity.jwt_utils import extract_bearer

        token = extract_bearer(auth_header)
        claims = verify_token(
            token, self._signing_key, self._issuer, self._audience, token_type="access"
        )
        if await self._store.is_jti_revoked(claims["jti"]):
            raise _unauthorized("revoked token")
        role = await self._store.get_member_role(claims["tid"], claims["sub"])
        if role is None:
            raise _unauthorized("membership revoked")
        claims["role"] = role
        return claims


def _role_scopes(role: str) -> list[str]:
    from fusion_identity.store import ROLES_SEED

    perms = ROLES_SEED.get(role, {}).get("permissions", {})
    scopes: list[str] = []
    for resource, actions in perms.items():
        for action in actions:
            scopes.append(f"{resource}:{action}")
    return scopes


def _unauthorized(detail: str):
    from fastapi import HTTPException

    return HTTPException(status_code=401, detail=detail)


async def bootstrap(store: InMemoryStore, admin_user: str | None, admin_pass: str | None) -> None:
    if not await store.is_empty_tenants():
        logger.info("bootstrap: tenants exist, skip")
        return
    if not admin_user or not admin_pass:
        logger.error(
            "bootstrap: empty tenants but FUSION_BOOTSTRAP_ADMIN_USER/PASS unset (fail-closed)"
        )
        raise RuntimeError(
            "bootstrap requires FUSION_BOOTSTRAP_ADMIN_USER and FUSION_BOOTSTRAP_ADMIN_PASS"
        )
    await store.create_tenant("default", "Default Tenant", plan="team")
    with contextlib.suppress(StoreConflict):
        await store.create_user("usr_admin", admin_user, admin_pass)
    await store.add_member("default", "usr_admin", "tenant_admin")
    logger.info("bootstrap: created default tenant + tenant_admin user=%s", admin_user)
