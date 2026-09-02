from __future__ import annotations

import contextlib
import logging
import secrets
import time
from typing import Any, Protocol

from fusion_identity.jwt_utils import issue_token, jwt_get_unverified_header, verify_token
from fusion_identity.models import (
    LoginRequest,
    MfaStatusResponse,
    MfaVerifyRequest,
    RefreshRequest,
    RevokeRequest,
    TokenResponse,
    VerifyRequest,
    VerifyResponse,
)
from fusion_identity.store import (
    LOCK_DURATION_SECONDS,
    LOCK_THRESHOLD,
    InMemoryStore,
    StoreConflict,
    hash_password,
    verify_password,
)

logger = logging.getLogger(__name__)


class StoreProto(Protocol):
    async def get_user_by_username(self, username: str) -> dict[str, Any] | None: ...
    async def get_user(self, user_id: str) -> dict[str, Any] | None: ...
    async def get_user_status(self, user_id: str) -> str | None: ...
    async def update_user(self, user_id: str, **fields: Any) -> dict[str, Any] | None: ...
    async def get_tenant_status(self, tenant_id: str) -> str | None: ...
    async def get_member_role(self, tenant_id: str, user_id: str) -> str | None: ...
    async def get_quota(self, tenant_id: str) -> dict[str, Any] | None: ...
    async def get_api_key_by_hash(self, key_hash: str) -> dict[str, Any] | None: ...
    async def is_jti_revoked(self, jti: str) -> bool: ...
    async def revoke_jti(
        self,
        jti: str,
        *,
        tenant_id: str = "",
        user_id: str | None = None,
        reason: str = "admin_revoke",
        expires_at: float | None = None,
    ) -> None: ...
    async def insert_refresh_token(
        self,
        jti: str,
        family_id: str,
        tenant_id: str,
        user_id: str,
        expires_at: float,
        replaced_by: str | None = None,
        status: str = "active",
    ) -> dict[str, Any]: ...
    async def get_refresh_token(self, jti: str) -> dict[str, Any] | None: ...
    async def rotate_refresh_token(self, old_jti: str, new_jti: str) -> bool: ...
    async def revoke_refresh_family(self, family_id: str) -> int: ...
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

    async def create_idp(
        self,
        idp_id: str,
        tenant_id: str,
        *,
        type: str = "oidc",
        issuer_url: str | None = None,
        client_id: str | None = None,
        client_secret_enc: str | None = None,
        scopes: str | None = None,
        auto_provision: bool = False,
    ) -> dict[str, Any]: ...

    async def get_idp(self, idp_id: str) -> dict[str, Any] | None: ...

    async def list_idps(self, tenant_id: str) -> list[dict[str, Any]]: ...

    async def delete_idp(self, idp_id: str) -> bool: ...

    async def upsert_mfa(
        self,
        user_id: str,
        method: str,
        *,
        secret_enc: str,
        enabled: bool = True,
    ) -> dict[str, Any]: ...

    async def get_mfa(self, user_id: str, method: str) -> dict[str, Any] | None: ...

    async def list_mfa(self, user_id: str) -> list[dict[str, Any]]: ...

    async def delete_mfa(self, user_id: str, method: str) -> bool: ...


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
        key_ring: Any = None,
        kek: str | None = None,
        mfa_enforce_admin: bool = False,
    ) -> None:
        self._store = store
        self._issuer = issuer
        self._audience = audience
        self._ttl = ttl
        self._refresh_ttl = refresh_ttl
        self._kek = kek or signing_key
        self._mfa_enforce_admin = mfa_enforce_admin
        if key_ring is not None:
            self._key_ring = key_ring
            self._signing_key = key_ring.signing_key()
            self._algorithm = key_ring.algorithm
            self._kid = key_ring.kid
        else:
            from fusion_identity.jwks import KeyRing

            self._key_ring = KeyRing.hs256(signing_key)
            self._signing_key = signing_key
            self._algorithm = "HS256"
            self._kid = None

    def _verify(self, token: str, *, token_type: str | None = None) -> dict[str, Any]:
        try:
            header = jwt_get_unverified_header(token)
        except Exception:
            header = {}
        hk = header.get("kid")
        key = self._key_ring.verify_key_for(hk)
        algos = [self._algorithm] if self._algorithm != "HS256" else ["HS256"]
        return verify_token(
            token,
            key,
            self._issuer,
            self._audience,
            token_type=token_type,
            algorithms=algos,
            kid=hk,
        )

    async def login(self, req: LoginRequest) -> TokenResponse:
        tenant_status = await self._store.get_tenant_status(req.tenant_id)
        if tenant_status in (None, "disabled", "deleted"):
            logger.warning("login: tenant=%s not active (%s)", req.tenant_id, tenant_status)
            raise _unauthorized("invalid credentials")
        user = await self._store.get_user_by_username(req.username)
        if user is None:
            logger.warning("login: unknown username=%s tid=%s", req.username, req.tenant_id)
            raise _unauthorized("invalid credentials")
        if _is_locked(user):
            logger.warning(
                "login: user=%s locked until %s", user["user_id"], user.get("locked_until")
            )
            raise _locked()
        ok, needs_rehash = verify_password(
            req.password,
            password_hash_v=user.get("password_hash_v", ""),
            password_hash=user.get("password_hash", ""),
            salt=user.get("salt", ""),
            algo=user.get("password_algo", "argon2id"),
        )
        if not ok:
            await self._record_failed_login(user, req.tenant_id)
            raise _unauthorized("invalid credentials")
        if needs_rehash:
            new_hash, new_salt, new_algo = hash_password(req.password)
            await self._store.update_user(
                user["user_id"],
                password_hash_v=new_hash,
                salt=new_salt,
                password_algo=new_algo,
            )
            logger.info("login: rehashed user=%s algo=%s", user["user_id"], new_algo)
        user_status = user.get("status", "active")
        if user_status in ("disabled", "locked"):
            logger.warning("login: user=%s status=%s", user["user_id"], user_status)
            raise _unauthorized("account disabled")
        role = await self._store.get_member_role(req.tenant_id, user["user_id"])
        if role is None:
            logger.warning("login: user=%s not member of tenant=%s", user["user_id"], req.tenant_id)
            raise _unauthorized("not a member of tenant")
        mfa_rec = await self._store.get_mfa(user["user_id"], "totp")
        mfa_required = bool(mfa_rec and mfa_rec.get("enabled"))
        enforce = self._mfa_enforce_admin and role == "tenant_admin"
        if enforce and not mfa_required:
            logger.warning(
                "login: admin=%s mfa enforced but not enrolled (tid=%s)",
                user["user_id"],
                req.tenant_id,
            )
            raise _unauthorized("mfa enrollment required for admin")
        if mfa_required:
            if not req.mfa_code:
                logger.info("login: mfa required user=%s", user["user_id"])
                return TokenResponse(
                    access_token="",
                    refresh_token="",
                    expires_in=0,
                    mfa_required=True,
                )
            if not _verify_totp(mfa_rec, req.mfa_code, self._kek):
                logger.warning("login: mfa code rejected user=%s", user["user_id"])
                await self._record_failed_login(user, req.tenant_id)
                raise _unauthorized("invalid mfa code")
        await self._store.update_user(
            user["user_id"],
            failed_attempts=0,
            locked_until=None,
            last_login_at=time.time(),
        )
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
            algorithm=self._algorithm,
            kid=self._kid,
        )
        family_id = secrets.token_hex(8)
        refresh, rjti = issue_token(
            sub=user["user_id"],
            tid=req.tenant_id,
            role=role,
            scopes=scopes,
            signing_key=self._signing_key,
            issuer=self._issuer,
            audience=self._audience,
            ttl_seconds=self._refresh_ttl,
            token_type="refresh",
            algorithm=self._algorithm,
            kid=self._kid,
        )
        await self._store.insert_refresh_token(
            rjti,
            family_id,
            req.tenant_id,
            user["user_id"],
            expires_at=time.time() + self._refresh_ttl,
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
        return TokenResponse(
            access_token=access,
            refresh_token=refresh,
            expires_in=self._ttl,
            must_change_password=bool(user.get("must_change_password")),
        )

    async def verify(self, req: VerifyRequest) -> VerifyResponse:
        claims = self._verify(req.token, token_type="access")
        jti = claims["jti"]
        if await self._store.is_jti_revoked(jti):
            logger.warning("verify: revoked jti=%s", jti)
            raise _unauthorized("revoked token")
        tenant_status = await self._store.get_tenant_status(claims["tid"])
        if tenant_status in (None, "disabled", "deleted"):
            logger.warning("verify: tenant=%s not active (%s)", claims["tid"], tenant_status)
            raise _unauthorized("tenant disabled")
        user_status = await self._store.get_user_status(claims["sub"])
        if user_status in ("disabled",):
            logger.warning("verify: user=%s disabled", claims["sub"])
            raise _unauthorized("account disabled")
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
            tid=claims["tid"],
            role=role,
            scopes=list(claims.get("scope", [])),
            quota=quota,
            tenant_status=tenant_status or "active",
        )

    async def introspect(self, token: str) -> dict[str, Any]:
        from fusion_identity.jwt_utils import JwtError

        inactive = {"active": False}
        try:
            claims = self._verify(token, token_type="access")
        except JwtError as exc:
            logger.info("introspect: rejected: %s", exc)
            return inactive
        jti = claims["jti"]
        if await self._store.is_jti_revoked(jti):
            logger.info("introspect: revoked jti=%s", jti)
            return inactive
        tenant_status = await self._store.get_tenant_status(claims["tid"])
        if tenant_status in (None, "disabled", "deleted"):
            logger.info("introspect: tenant=%s not active", claims["tid"])
            return inactive
        role = await self._store.get_member_role(claims["tid"], claims["sub"])
        if role is None:
            logger.info("introspect: membership gone sub=%s", claims["sub"])
            return inactive
        if role != claims.get("role"):
            claims["role"] = role
            claims["scope"] = _role_scopes(role)
        user = await self._store.get_user(claims["sub"])
        username = (user or {}).get("username")
        scopes = list(claims.get("scope", []))
        logger.info("introspect: active sub=%s tid=%s", claims["sub"], claims["tid"])
        return {
            "active": True,
            "scope": " ".join(scopes),
            "client_id": claims["tid"],
            "username": username,
            "sub": claims["sub"],
            "tenant_id": claims["tid"],
            "role": role,
            "token_type": "Bearer",
            "iat": claims.get("iat"),
            "exp": claims.get("exp"),
            "jti": jti,
            "iss": claims.get("iss"),
            "aud": claims.get("aud"),
        }

    async def refresh(self, req: RefreshRequest) -> TokenResponse:
        claims = self._verify(req.refresh_token, token_type="refresh")
        jti = claims["jti"]
        rt = await self._store.get_refresh_token(jti)
        if rt is None:
            logger.warning("refresh: unknown jti=%s", jti)
            raise _unauthorized("invalid refresh token")
        if rt["status"] == "revoked":
            raise _unauthorized("revoked refresh token")
        if rt["status"] == "rotated":
            logger.warning("refresh: reuse detected jti=%s family=%s", jti, rt["family_id"])
            await self._store.revoke_refresh_family(rt["family_id"])
            await self._store.append_audit(
                claims["tid"],
                claims["sub"],
                jti,
                None,
                "auth.refresh_reuse",
                "session",
                {"family_id": rt["family_id"]},
            )
            raise _unauthorized("refresh token reuse detected")
        tenant_status = await self._store.get_tenant_status(claims["tid"])
        if tenant_status in (None, "disabled", "deleted"):
            raise _unauthorized("tenant disabled")
        user_status = await self._store.get_user_status(claims["sub"])
        if user_status in ("disabled",):
            raise _unauthorized("account disabled")
        role = await self._store.get_member_role(claims["tid"], claims["sub"])
        if role is None:
            raise _unauthorized("membership revoked")
        scopes = _role_scopes(role)
        access, ajti = issue_token(
            sub=claims["sub"],
            tid=claims["tid"],
            role=role,
            scopes=scopes,
            signing_key=self._signing_key,
            issuer=self._issuer,
            audience=self._audience,
            ttl_seconds=self._ttl,
            token_type="access",
            algorithm=self._algorithm,
            kid=self._kid,
        )
        new_family_id = rt["family_id"]
        new_refresh, nrjti = issue_token(
            sub=claims["sub"],
            tid=claims["tid"],
            role=role,
            scopes=scopes,
            signing_key=self._signing_key,
            issuer=self._issuer,
            audience=self._audience,
            ttl_seconds=self._refresh_ttl,
            token_type="refresh",
            algorithm=self._algorithm,
            kid=self._kid,
        )
        await self._store.rotate_refresh_token(jti, nrjti)
        await self._store.insert_refresh_token(
            nrjti,
            new_family_id,
            claims["tid"],
            claims["sub"],
            expires_at=time.time() + self._refresh_ttl,
        )
        await self._store.append_audit(
            claims["tid"],
            claims["sub"],
            ajti,
            role,
            "auth.refresh",
            "session",
            {"rotated_from": jti},
        )
        return TokenResponse(access_token=access, refresh_token=new_refresh, expires_in=self._ttl)

    async def revoke(
        self, req: RevokeRequest, caller_tid: str, caller_uid: str | None
    ) -> dict[str, Any]:
        await self._store.revoke_jti(
            req.jti,
            tenant_id=caller_tid,
            user_id=caller_uid,
            reason="admin_revoke",
        )
        await self._store.append_audit(
            caller_tid, caller_uid, req.jti, None, "auth.revoke", "session", {"jti": req.jti}
        )
        return {"revoked": True, "jti": req.jti}

    async def logout(self, claims: dict[str, Any], refresh_token: str | None) -> dict[str, Any]:
        await self._store.revoke_jti(
            claims["jti"],
            tenant_id=claims["tid"],
            user_id=claims["sub"],
            reason="logout",
            expires_at=claims.get("exp", time.time()),
        )
        if refresh_token:
            with contextlib.suppress(Exception):
                rclaims = self._verify(refresh_token, token_type="refresh")
                rt = await self._store.get_refresh_token(rclaims["jti"])
                if rt:
                    await self._store.revoke_refresh_family(rt["family_id"])
        await self._store.append_audit(
            claims["tid"],
            claims["sub"],
            claims["jti"],
            claims.get("role"),
            "auth.logout",
            "session",
            {},
        )
        return {"logged_out": True}

    async def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
        *,
        tenant_id: str = "",
    ) -> dict[str, Any]:
        user = await self._store.get_user(user_id)
        if user is None:
            raise _unauthorized("user not found")
        ok, _ = verify_password(
            old_password,
            password_hash_v=user.get("password_hash_v", ""),
            password_hash=user.get("password_hash", ""),
            salt=user.get("salt", ""),
            algo=user.get("password_algo", "argon2id"),
        )
        if not ok:
            raise _unauthorized("invalid credentials")
        pw_hash, salt, algo = hash_password(new_password)
        await self._store.update_user(
            user_id,
            password_hash_v=pw_hash,
            salt=salt,
            password_algo=algo,
            must_change_password=False,
        )
        await self._store.append_audit(
            tenant_id,
            user_id,
            None,
            None,
            "auth.password_change",
            "session",
            {},
        )
        return {"changed": True}

    async def enroll_mfa(self, user_id: str) -> dict[str, Any]:
        import pyotp

        from fusion_identity.crypto import encrypt_secret

        raw = pyotp.random_base32()
        rec = await self._store.upsert_mfa(
            user_id, "totp", secret_enc=encrypt_secret(raw, self._kek)
        )
        user = await self._store.get_user(user_id)
        label = (user or {}).get("username", user_id)
        uri = pyotp.TOTP(raw).provisioning_uri(name=label, issuer_name="fusion-identity")
        logger.warning("enroll_mfa: user=%s totp secret generated", user_id)
        return {"method": "totp", "secret": raw, "otpauth_uri": uri, "enabled": rec["enabled"]}

    async def verify_mfa(self, user_id: str, req: MfaVerifyRequest) -> MfaStatusResponse:
        import pyotp

        from fusion_identity.crypto import decrypt_secret

        rec = await self._store.get_mfa(user_id, req.method)
        if rec is None:
            raise _unauthorized("mfa not enrolled")
        raw = decrypt_secret(rec["secret_enc"], self._kek)
        if not pyotp.TOTP(raw).verify(req.code, valid_window=1):
            logger.warning("verify_mfa: bad code user=%s", user_id)
            raise _unauthorized("invalid mfa code")
        await self._store.upsert_mfa(
            user_id, req.method, secret_enc=rec["secret_enc"], enabled=True
        )
        logger.info("verify_mfa: enabled user=%s method=%s", user_id, req.method)
        return MfaStatusResponse(
            method=req.method, enabled=True, enrolled_at=rec.get("enrolled_at")
        )

    async def list_mfa(self, user_id: str) -> list[dict[str, Any]]:
        rows = await self._store.list_mfa(user_id)
        return [
            {"method": r["method"], "enabled": r["enabled"], "enrolled_at": r.get("enrolled_at")}
            for r in rows
        ]

    async def delete_mfa(self, user_id: str, method: str) -> bool:
        ok = await self._store.delete_mfa(user_id, method)
        logger.warning("delete_mfa: user=%s method=%s ok=%s", user_id, method, ok)
        return ok

    async def resolve_bearer_claims(self, auth_header: str) -> dict[str, Any]:
        from fusion_identity.jwt_utils import JwtError, extract_bearer

        try:
            token = extract_bearer(auth_header)
            claims = self._verify(token, token_type="access")
        except JwtError as exc:
            logger.warning("resolve_bearer_claims: rejected: %s", exc)
            raise _unauthorized("invalid token") from exc
        if await self._store.is_jti_revoked(claims["jti"]):
            raise _unauthorized("revoked token")
        tenant_status = await self._store.get_tenant_status(claims["tid"])
        if tenant_status in (None, "disabled", "deleted"):
            raise _unauthorized("tenant disabled")
        role = await self._store.get_member_role(claims["tid"], claims["sub"])
        if role is None:
            raise _unauthorized("membership revoked")
        claims["role"] = role
        claims["scope"] = _role_scopes(role)
        return claims

    async def _record_failed_login(self, user: dict[str, Any], tenant_id: str) -> None:
        attempts = user.get("failed_attempts", 0) + 1
        fields: dict[str, Any] = {"failed_attempts": attempts}
        if attempts >= LOCK_THRESHOLD:
            fields["locked_until"] = time.time() + LOCK_DURATION_SECONDS
            await self._store.append_audit(
                tenant_id,
                user["user_id"],
                None,
                None,
                "auth.account_locked",
                "session",
                {"attempts": attempts},
            )
        await self._store.update_user(user["user_id"], **fields)
        with contextlib.suppress(Exception):
            await self._store.append_audit(
                tenant_id,
                user["user_id"],
                None,
                None,
                "auth.login_failed",
                "session",
                {"username": user["username"]},
            )


def _verify_totp(mfa_rec: dict[str, Any], code: str, kek: str) -> bool:
    import pyotp

    from fusion_identity.crypto import decrypt_secret

    raw = decrypt_secret(mfa_rec["secret_enc"], kek)
    return pyotp.TOTP(raw).verify(code, valid_window=1)


def _is_locked(user: dict[str, Any]) -> bool:
    lu = user.get("locked_until")
    if lu is None:
        return False
    return isinstance(lu, (int, float)) and lu > time.time()


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


def _locked():
    from fastapi import HTTPException

    return HTTPException(status_code=429, detail="account locked, retry later")


async def bootstrap(
    store: InMemoryStore,
    admin_user: str | None,
    admin_pass: str | None,
    bootstrap_tenants: str | None = None,
) -> None:
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
        await store.create_user(
            "usr_admin",
            admin_user,
            admin_pass,
            must_change_password=False,
        )
    await store.add_member("default", "usr_admin", "tenant_admin")
    logger.info("bootstrap: created default tenant + tenant_admin user=%s", admin_user)

    if bootstrap_tenants:
        import json as _json

        try:
            extra = _json.loads(bootstrap_tenants)
        except (ValueError, TypeError) as exc:
            logger.error("bootstrap: invalid FUSION_BOOTSTRAP_TENANTS JSON: %s", exc)
            raise RuntimeError(f"invalid FUSION_BOOTSTRAP_TENANTS JSON: {exc}") from exc
        if not isinstance(extra, list):
            raise RuntimeError("FUSION_BOOTSTRAP_TENANTS must be a JSON array")
        for item in extra:
            if not isinstance(item, dict) or not item.get("tenant_id"):
                raise RuntimeError("bootstrap tenant entry missing tenant_id")
            tid = str(item["tenant_id"])
            display = str(item.get("display_name", tid))
            plan = str(item.get("plan", "team"))
            with contextlib.suppress(StoreConflict):
                await store.create_tenant(tid, display, plan=plan)
            logger.info("bootstrap: seeded tenant=%s plan=%s", tid, plan)
