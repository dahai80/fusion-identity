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

# L17: a real argon2id hash of a random dummy password, computed once at import
# so the unknown-username login path runs a comparable KDF (no timing side
# channel for username enumeration).
_DUMMY_HASH_V = hash_password("fusion-identity-dummy-non secret")[0]


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
    async def record_issued_jti(self, jti: str, tenant_id: str, user_id: str) -> None: ...
    async def get_jti_owner(self, jti: str) -> tuple[str, str | None] | None: ...
    async def revoke_user_sessions(self, user_id: str) -> int: ...
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
        else:
            from fusion_identity.jwks import KeyRing

            self._key_ring = KeyRing.hs256(signing_key)
        # F17: do NOT snapshot signing_key/kid/algorithm here — read them live
        # from the key ring on every issue/verify so rotate() takes effect.

    def _signing_key(self) -> str:
        # F17: live read so rotate() changes the signing material immediately.
        return self._key_ring.signing_key()

    @property
    def _algorithm(self) -> str:
        # F17: live read — rotate() may switch algorithm (e.g. RS256 rotation).
        return self._key_ring.algorithm

    @property
    def _kid(self) -> str | None:
        # F17: live read of the current kid.
        return self._key_ring.kid

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

    async def _authorize(self, claims: dict[str, Any]) -> str:
        # L19/F6: single authorization predicate shared by verify/introspect/
        # refresh/resolve_bearer_claims. Fail-closed on revoked jti, tenant
        # status, user status (None == deleted == deny), and membership.
        jti = claims["jti"]
        if await self._store.is_jti_revoked(jti):
            logger.warning("_authorize: revoked jti=%s", jti)
            raise _unauthorized("revoked token")
        tenant_status = await self._store.get_tenant_status(claims["tid"])
        if tenant_status in (None, "disabled", "deleted"):
            logger.warning("_authorize: tenant=%s not active (%s)", claims["tid"], tenant_status)
            raise _unauthorized("tenant disabled")
        user_status = await self._store.get_user_status(claims["sub"])
        # F6: None (deleted user) must deny, not pass. Locked also denies.
        if user_status in (None, "disabled", "locked"):
            logger.warning("_authorize: user=%s status=%s — deny", claims["sub"], user_status)
            raise _unauthorized("account disabled")
        role = await self._store.get_member_role(claims["tid"], claims["sub"])
        if role is None:
            logger.warning(
                "_authorize: membership gone sub=%s tid=%s", claims["sub"], claims["tid"]
            )
            raise _unauthorized("membership revoked")
        if role != claims.get("role"):
            logger.warning(
                "_authorize: role drift token=%s db=%s sub=%s",
                claims.get("role"),
                role,
                claims["sub"],
            )
            claims["role"] = role
            claims["scope"] = _role_scopes(role)
        return role

    async def login(self, req: LoginRequest) -> TokenResponse:
        tenant_status = await self._store.get_tenant_status(req.tenant_id)
        if tenant_status in (None, "disabled", "deleted"):
            logger.warning("login: tenant=%s not active (%s)", req.tenant_id, tenant_status)
            raise _unauthorized("invalid credentials")
        user = await self._store.get_user_by_username(req.username)
        if user is None:
            # L17: run a dummy KDF so the unknown-username path takes roughly
            # the same time as the known-username path (no enumeration side channel).
            verify_password(
                req.password,
                password_hash_v=_DUMMY_HASH_V,
                password_hash="",
                salt="",
                algo="argon2id",
            )
            logger.warning("login: unknown username=%s tid=%s", req.username, req.tenant_id)
            raise _unauthorized("invalid credentials")
        if _is_locked(user):
            logger.warning(
                "login: user=%s locked until %s", user["user_id"], user.get("locked_until")
            )
            raise _locked()
        # L15: check user status BEFORE the expensive KDF so disabled accounts
        # fail fast instead of revealing the disabled state via timing.
        user_status = user.get("status", "active")
        if user_status in ("disabled", "locked"):
            logger.warning("login: user=%s status=%s", user["user_id"], user_status)
            raise _unauthorized("account disabled")
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
            signing_key=self._signing_key(),
            issuer=self._issuer,
            audience=self._audience,
            ttl_seconds=self._ttl,
            token_type="access",
            algorithm=self._algorithm,
            kid=self._kid,
        )
        # F4: record ownership so /revoke can bind the access jti to its tenant.
        await self._store.record_issued_jti(jti, req.tenant_id, user["user_id"])
        family_id = secrets.token_hex(8)
        refresh, rjti = issue_token(
            sub=user["user_id"],
            tid=req.tenant_id,
            role=role,
            scopes=scopes,
            signing_key=self._signing_key(),
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
        # L19/F6: shared authorization predicate (fail-closed on deleted user).
        await self._authorize(claims)
        tenant_status = await self._store.get_tenant_status(claims["tid"])
        quota = await self._store.get_quota(claims["tid"]) or {}
        return VerifyResponse(
            tid=claims["tid"],
            role=claims["role"],
            scopes=list(claims.get("scope", [])),
            quota=quota,
            tenant_status=tenant_status or "active",
        )

    async def introspect(self, token: str) -> dict[str, Any]:
        from fastapi import HTTPException

        from fusion_identity.jwt_utils import JwtError

        inactive = {"active": False}
        try:
            claims = self._verify(token, token_type="access")
        except JwtError as exc:
            logger.info("introspect: rejected: %s", exc)
            return inactive
        # L19/F6: shared authorization predicate. introspect returns inactive
        # (not 401) on any denial, so wrap _authorize's HTTPException.
        try:
            await self._authorize(claims)
        except HTTPException as exc:
            logger.info("introspect: inactive (%s): %s", exc.status_code, exc.detail)
            return inactive
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
            "role": claims["role"],
            "token_type": "Bearer",
            "iat": claims.get("iat"),
            "exp": claims.get("exp"),
            "jti": claims["jti"],
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
        # L19/F6: shared authorization predicate (fail-closed on deleted user,
        # revoked jti, membership). refresh does not call _authorize directly
        # because the jti revocation check above is against the refresh-token
        # ledger, not the access-token revoked_jtis set — but user/tenant/
        # membership status must still be fail-closed here.
        user_status = await self._store.get_user_status(claims["sub"])
        if user_status in (None, "disabled", "locked"):
            raise _unauthorized("account disabled")
        role = await self._store.get_member_role(claims["tid"], claims["sub"])
        if role is None:
            raise _unauthorized("membership revoked")
        scopes = _role_scopes(role)
        new_family_id = rt["family_id"]
        new_refresh, nrjti = issue_token(
            sub=claims["sub"],
            tid=claims["tid"],
            role=role,
            scopes=scopes,
            signing_key=self._signing_key(),
            issuer=self._issuer,
            audience=self._audience,
            ttl_seconds=self._refresh_ttl,
            token_type="refresh",
            algorithm=self._algorithm,
            kid=self._kid,
        )
        # F7: CAS — rotate_refresh_token returns False if the old jti was no
        # longer 'active' (concurrent refresh won the race). On False, treat it
        # as reuse: revoke the whole family and refuse. Must happen BEFORE
        # issuing the access token and inserting the new refresh record.
        ok = await self._store.rotate_refresh_token(jti, nrjti)
        if not ok:
            logger.warning("refresh: CAS lost jti=%s family=%s — reuse path", jti, rt["family_id"])
            await self._store.revoke_refresh_family(rt["family_id"])
            await self._store.append_audit(
                claims["tid"],
                claims["sub"],
                jti,
                None,
                "auth.refresh_reuse",
                "session",
                {"family_id": rt["family_id"], "reason": "cas_lost"},
            )
            raise _unauthorized("refresh token reuse detected")
        access, ajti = issue_token(
            sub=claims["sub"],
            tid=claims["tid"],
            role=role,
            scopes=scopes,
            signing_key=self._signing_key(),
            issuer=self._issuer,
            audience=self._audience,
            ttl_seconds=self._ttl,
            token_type="access",
            algorithm=self._algorithm,
            kid=self._kid,
        )
        # F4: record ownership of the new access jti.
        await self._store.record_issued_jti(ajti, claims["tid"], claims["sub"])
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
        # F4: ownership — jti must belong to the caller's tenant. Without this,
        # a tenant_admin of A could revoke tokens issued to tenant B by guessing
        # or enumerating a jti. Cross-tenant revoke denied.
        owner = await self._store.get_jti_owner(req.jti)
        if owner is None:
            logger.warning("revoke: jti=%s has no known owner — denied", req.jti)
            raise _forbidden("jti does not belong to caller tenant")
        owner_tid, _owner_uid = owner
        if owner_tid != caller_tid:
            logger.warning(
                "revoke: cross-tenant denied jti=%s owner=%s caller=%s",
                req.jti,
                owner_tid,
                caller_tid,
            )
            raise _forbidden("jti does not belong to caller tenant")
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
            # F18: only the decode step may be suppressed (a stale/invalid
            # refresh token on logout should not block the logout). Store
            # failures (get_refresh_token / revoke_refresh_family) must
            # propagate — swallowing them hides a broken store behind a
            # silent 200, violating fail-closed.
            rclaims = None
            with contextlib.suppress(Exception):
                rclaims = self._verify(refresh_token, token_type="refresh")
            if rclaims is not None:
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
            # L11: a wrong old-password attempt is a login failure against this
            # account — record it so the lockout counter advances, instead of
            # silently 401-ing. This closes an account-takeover bypass where an
            # attacker could brute-force the old password via change_password
            # without tripping the lock.
            await self._record_failed_login(user, tenant_id)
            raise _unauthorized("invalid credentials")
        pw_hash, salt, algo = hash_password(new_password)
        await self._store.update_user(
            user_id,
            password_hash_v=pw_hash,
            salt=salt,
            password_algo=algo,
            must_change_password=False,
        )
        # L10: password change invalidates all existing sessions — revoke every
        # refresh token issued to this user so no old credential survives the
        # rotation. The current caller's access token expires on its own TTL.
        revoked = await self._store.revoke_user_sessions(user_id)
        logger.info("change_password: user=%s revoked_sessions=%s", user_id, revoked)
        await self._store.append_audit(
            tenant_id,
            user_id,
            None,
            None,
            "auth.password_change",
            "session",
            {"revoked_sessions": revoked},
        )
        return {"changed": True}

    async def enroll_mfa(self, user_id: str) -> dict[str, Any]:
        import pyotp

        from fusion_identity.crypto import encrypt_secret

        raw = pyotp.random_base32()
        # L12: a freshly generated TOTP secret must be enrolled disabled — the
        # factor is only active after verify_mfa proves the user can produce a
        # valid code. Storing enabled=True here would let an attacker lock the
        # real user out by enrolling a factor the user never validated, or skip
        # the verification step entirely.
        rec = await self._store.upsert_mfa(
            user_id, "totp", secret_enc=encrypt_secret(raw, self._kek), enabled=False
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
        # F6/L19: fail-closed on user status — a deleted/disabled/locked account
        # must not pass even with a valid signature. None means no user record
        # (deleted) → deny.
        user_status = await self._store.get_user_status(claims["sub"])
        if user_status in (None, "disabled", "locked"):
            raise _unauthorized("account disabled")
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
        # M7: do not suppress append_audit failures. A swallowed audit error
        # here would let the failed-login counter advance silently while the
        # audit trail loses the record — the security event must surface.
        try:
            await self._store.append_audit(
                tenant_id,
                user["user_id"],
                None,
                None,
                "auth.login_failed",
                "session",
                {"username": user["username"]},
            )
        except Exception:
            logger.exception(
                "login_failed audit append failed user=%s tenant=%s", user["user_id"], tenant_id
            )
            raise


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


def _forbidden(detail: str):
    from fastapi import HTTPException

    return HTTPException(status_code=403, detail=detail)


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
    # L16: do not swallow StoreConflict on create_user. We are in the
    # empty-tenants branch, so a pre-existing usr_admin is an inconsistent
    # state — surfacing it (rather than silently skipping) prevents bootstrap
    # from wiring a stale/foreign admin into the default tenant.
    try:
        await store.create_user(
            "usr_admin",
            admin_user,
            admin_pass,
            must_change_password=False,
        )
    except StoreConflict as exc:
        logger.error("bootstrap: usr_admin already exists in empty-tenant state: %s", exc)
        raise RuntimeError("bootstrap conflict: usr_admin already exists") from exc
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
            # L16: same reasoning — a conflicting extra tenant in the empty
            # branch is inconsistent; surface instead of swallowing.
            await store.create_tenant(tid, display, plan=plan)
            logger.info("bootstrap: seeded tenant=%s plan=%s", tid, plan)
