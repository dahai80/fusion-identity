from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any

logger = logging.getLogger(__name__)

ROLES_SEED = {
    "tenant_admin": {
        "display_name": "Tenant Admin",
        "permissions": {
            "tenants": ["read", "write"],
            "users": ["read", "write"],
            "quotas": ["read", "write"],
            "audit": ["read"],
        },
    },
    "operator": {
        "display_name": "Operator",
        "permissions": {"models": ["read", "infer"], "tasks": ["read", "write"]},
    },
    "member": {
        "display_name": "Member",
        "permissions": {"models": ["infer"], "tasks": ["write"]},
    },
    "viewer": {
        "display_name": "Viewer",
        "permissions": {"models": ["read"], "tasks": ["read"]},
    },
}

DEFAULT_QUOTA = {
    "rpm": 60,
    "tpm": 100000,
    "concurrent": 4,
    "storage_mb": 10240,
    "allowed_models": [],
    "allowed_modules": [],
    "default_priority": 0,
}

LEGACY_SALT = "fusion-identity"
LOCK_THRESHOLD = 5
LOCK_DURATION_SECONDS = 15 * 60


def _gen_salt() -> str:
    return secrets.token_bytes(16).hex()


def _argon2_hash(password: str, salt: str) -> str:
    from argon2 import PasswordHasher, low_level

    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, type=low_level.Type.ID)
    salt_bytes = bytes.fromhex(salt)
    return ph.hash(password.encode(), salt=salt_bytes)


def hash_password(password: str, salt: str | None = None) -> tuple[str, str, str]:
    s = salt or _gen_salt()
    h = _argon2_hash(password, s)
    return h, s, "argon2id"


def _scrypt_legacy(password: str, salt: str = LEGACY_SALT) -> str:
    return hashlib.scrypt(
        password.encode(),
        salt=salt.encode(),
        n=16384,
        r=8,
        p=1,
        dklen=32,
    ).hex()


def scrypt_hash(password: str, salt: str = LEGACY_SALT) -> str:
    return _scrypt_legacy(password, salt)


def verify_password(
    password: str,
    *,
    password_hash_v: str = "",
    password_hash: str = "",
    salt: str = "",
    algo: str = "argon2id",
) -> tuple[bool, bool]:
    needs_rehash = False
    try:
        if algo == "argon2id" and password_hash_v:
            from argon2 import PasswordHasher
            from argon2.exceptions import InvalidHashError, VerifyMismatchError

            ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
            try:
                ph.verify(password_hash_v, password)
                needs_rehash = ph.check_needs_rehash(password_hash_v)
            except (VerifyMismatchError, InvalidHashError):
                return False, False
            return True, needs_rehash
        if algo == "scrypt" or (algo == "legacy" and password_hash):
            candidate = _scrypt_legacy(password, salt or LEGACY_SALT)
            ok = hmac.compare_digest(candidate, password_hash)
            return ok, ok
        if password_hash:
            candidate = _scrypt_legacy(password, LEGACY_SALT)
            ok = hmac.compare_digest(candidate, password_hash)
            return ok, ok
    except (ValueError, TypeError) as exc:
        logger.warning("verify_password failed: %s", exc)
        return False, False
    return False, False


def sha256_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _chain_hash(prev_hash: str, fields: dict[str, Any]) -> str:
    payload = prev_hash + json.dumps(fields, default=str, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _audit_fields(
    tenant_id: str,
    user_id: str | None,
    jti: str | None,
    role: str | None,
    action: str,
    resource: str | None,
    detail: Any,
    ts: float,
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "jti": jti,
        "role": role,
        "action": action,
        "resource": resource,
        "detail": detail,
        "ts": ts,
    }


class StoreConflict(RuntimeError):
    pass


class InMemoryStore:
    def __init__(self) -> None:
        self._tenants: dict[str, dict[str, Any]] = {}
        self._users: dict[str, dict[str, Any]] = {}
        self._members: dict[tuple[str, str], dict[str, Any]] = {}
        self._api_keys: dict[str, dict[str, Any]] = {}
        self._key_hash_index: dict[str, str] = {}
        self._quotas: dict[str, dict[str, Any]] = {}
        self._audit: list[dict[str, Any]] = []
        self._revoked_jtis: dict[str, dict[str, Any]] = {}
        self._refresh_tokens: dict[str, dict[str, Any]] = {}
        self._roles = {k: dict(v) for k, v in ROLES_SEED.items()}
        self._seq_audit = 0
        self._usage: list[dict[str, Any]] = []
        self._idps: dict[str, dict[str, Any]] = {}
        self._mfa: dict[tuple[str, str], dict[str, Any]] = {}
        self._lease_log: list[dict[str, Any]] = []
        logger.info(
            "InMemoryStore initialized (roles seeded=%d) — NOT for production", len(self._roles)
        )

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def ensure_schema(self) -> None:
        pass

    async def is_empty_tenants(self) -> bool:
        return len(self._tenants) == 0

    async def create_tenant(
        self, tenant_id: str, display_name: str, plan: str = "team"
    ) -> dict[str, Any]:
        if tenant_id in self._tenants:
            raise StoreConflict(f"tenant {tenant_id} exists")
        now = _now()
        self._tenants[tenant_id] = {
            "tenant_id": tenant_id,
            "display_name": display_name,
            "status": "active",
            "plan": plan,
            "created_at": now,
            "disabled_at": None,
            "deleted_at": None,
        }
        self._quotas[tenant_id] = {"tenant_id": tenant_id, "updated_at": now, **DEFAULT_QUOTA}
        logger.info("create_tenant: %s plan=%s", tenant_id, plan)
        return dict(self._tenants[tenant_id])

    async def get_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        t = self._tenants.get(tenant_id)
        return dict(t) if t else None

    async def get_tenant_status(self, tenant_id: str) -> str | None:
        t = self._tenants.get(tenant_id)
        return t["status"] if t else None

    async def list_tenants(self) -> list[dict[str, Any]]:
        return [dict(t) for t in self._tenants.values() if t["status"] != "deleted"]

    async def list_tenants_for(self, tenant_id: str) -> list[dict[str, Any]]:
        t = self._tenants.get(tenant_id)
        if not t or t["status"] == "deleted":
            return []
        return [dict(t)]

    async def update_tenant(self, tenant_id: str, **fields: Any) -> dict[str, Any] | None:
        t = self._tenants.get(tenant_id)
        if not t:
            return None
        for k in ("display_name", "status", "plan"):
            if k in fields and fields[k] is not None:
                t[k] = fields[k]
        if t["status"] == "disabled" and not t["disabled_at"]:
            t["disabled_at"] = _now()
        if t["status"] == "active":
            t["disabled_at"] = None
        return dict(t)

    async def delete_tenant(self, tenant_id: str) -> bool:
        t = self._tenants.get(tenant_id)
        if not t:
            return False
        t["status"] = "deleted"
        t["deleted_at"] = _now()
        for tid, _uid in list(self._members.keys()):
            if tid == tenant_id:
                self._members.pop((tid, _uid), None)
        for k in list(self._api_keys.values()):
            if k["tenant_id"] == tenant_id and not k["revoked_at"]:
                k["revoked_at"] = _now()
                self._key_hash_index.pop(k["key_hash"], None)
        for r in self._refresh_tokens.values():
            if r["tenant_id"] == tenant_id and r["status"] != "revoked":
                r["status"] = "revoked"
        logger.info("delete_tenant: cascaded tenant=%s (members/keys/refresh revoked)", tenant_id)
        return True

    async def create_user(
        self,
        user_id: str,
        username: str,
        password: str,
        email: str | None = None,
        *,
        must_change_password: bool = False,
    ) -> dict[str, Any]:
        if user_id in self._users:
            raise StoreConflict(f"user {user_id} exists")
        pw_hash, salt, algo = hash_password(password)
        self._users[user_id] = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "password_hash": "",
            "password_hash_v": pw_hash,
            "salt": salt,
            "password_algo": algo,
            "status": "active",
            "failed_attempts": 0,
            "locked_until": None,
            "must_change_password": must_change_password,
            "last_login_at": None,
            "created_at": _now(),
        }
        logger.info("create_user: %s username=%s", user_id, username)
        return dict(self._users[user_id])

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        for u in self._users.values():
            if u["username"] == username:
                return dict(u)
        return None

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        u = self._users.get(user_id)
        return dict(u) if u else None

    async def get_user_status(self, user_id: str) -> str | None:
        u = self._users.get(user_id)
        return u["status"] if u else None

    async def update_user(self, user_id: str, **fields: Any) -> dict[str, Any] | None:
        u = self._users.get(user_id)
        if not u:
            return None
        for k in (
            "password_hash",
            "password_hash_v",
            "salt",
            "password_algo",
            "status",
            "failed_attempts",
            "locked_until",
            "must_change_password",
            "last_login_at",
            "display_name",
            "email",
        ):
            if k in fields and fields[k] is not None:
                u[k] = fields[k]
        return dict(u)

    async def add_member(
        self, tenant_id: str, user_id: str, role: str, added_by: str | None = None
    ) -> dict[str, Any]:
        if role not in ROLES_SEED:
            raise StoreConflict(f"unknown role {role}")
        key = (tenant_id, user_id)
        self._members[key] = {
            "tenant_id": tenant_id,
            "user_id": user_id,
            "role": role,
            "added_by": added_by,
            "added_at": _now(),
            "joined_at": _now(),
        }
        return dict(self._members[key])

    async def get_member(self, tenant_id: str, user_id: str) -> dict[str, Any] | None:
        m = self._members.get((tenant_id, user_id))
        return dict(m) if m else None

    async def get_member_role(self, tenant_id: str, user_id: str) -> str | None:
        m = self._members.get((tenant_id, user_id))
        return m["role"] if m else None

    async def update_member_role(
        self, tenant_id: str, user_id: str, role: str
    ) -> dict[str, Any] | None:
        if role not in ROLES_SEED:
            raise StoreConflict(f"unknown role {role}")
        m = self._members.get((tenant_id, user_id))
        if not m:
            return None
        m["role"] = role
        return dict(m)

    async def list_members(self, tenant_id: str) -> list[dict[str, Any]]:
        return [dict(m) for (tid, _), m in self._members.items() if tid == tenant_id]

    async def log_lease(
        self, tenant_id: str, lease_id: str, action: str, reason: str | None = None
    ) -> None:
        rec = {
            "tenant_id": tenant_id,
            "lease_id": lease_id,
            "action": action,
            "reason": reason,
            "created_at": _now(),
        }
        self._lease_log.append(rec)
        logger.debug("log_lease: tenant=%s lease=%s action=%s", tenant_id, lease_id, action)

    async def list_lease_log(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = [r for r in self._lease_log if r["tenant_id"] == tenant_id]
        return list(reversed(rows[-limit:]))

    async def count_members_by_role(self, tenant_id: str, role: str) -> int:
        return sum(
            1 for (tid, _), m in self._members.items() if tid == tenant_id and m["role"] == role
        )

    async def remove_member(self, tenant_id: str, user_id: str) -> bool:
        return self._members.pop((tenant_id, user_id), None) is not None

    async def create_api_key(
        self, tenant_id: str, user_id: str | None, scopes: list[str]
    ) -> tuple[str, dict[str, Any]]:
        raw = "fmu_" + secrets.token_urlsafe(24)
        key_id = "key_" + secrets.token_hex(6)
        key_hash = sha256_hash(raw)
        record = {
            "key_id": key_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "key_hash": key_hash,
            "prefix": raw[:8] + "****",
            "scopes": list(scopes),
            "created_at": _now(),
            "revoked_at": None,
        }
        self._api_keys[key_id] = record
        self._key_hash_index[key_hash] = key_id
        logger.info("create_api_key: %s tenant=%s user=%s", key_id, tenant_id, user_id)
        return raw, dict(record)

    async def get_api_key_by_hash(self, key_hash: str) -> dict[str, Any] | None:
        key_id = self._key_hash_index.get(key_hash)
        if not key_id:
            return None
        k = self._api_keys.get(key_id)
        if not k or k["revoked_at"]:
            return None
        return dict(k)

    async def list_api_keys(self, tenant_id: str) -> list[dict[str, Any]]:
        return [
            dict(k)
            for k in self._api_keys.values()
            if k["tenant_id"] == tenant_id and not k["revoked_at"]
        ]

    async def revoke_api_key(self, key_id: str) -> bool:
        k = self._api_keys.get(key_id)
        if not k:
            return False
        k["revoked_at"] = _now()
        self._key_hash_index.pop(k["key_hash"], None)
        return True

    async def get_quota(self, tenant_id: str) -> dict[str, Any] | None:
        q = self._quotas.get(tenant_id)
        return dict(q) if q else None

    async def put_quota(self, tenant_id: str, **fields: Any) -> dict[str, Any] | None:
        q = self._quotas.get(tenant_id)
        if not q:
            return None
        for k in (
            "rpm",
            "tpm",
            "concurrent",
            "storage_mb",
            "allowed_models",
            "allowed_modules",
            "default_priority",
        ):
            if k in fields and fields[k] is not None:
                q[k] = fields[k]
        q["updated_at"] = _now()
        return dict(q)

    async def append_audit(
        self,
        tenant_id: str,
        user_id: str | None,
        jti: str | None,
        role: str | None,
        action: str,
        resource: str | None,
        detail: Any,
    ) -> dict[str, Any]:
        self._seq_audit += 1
        ts = _now()
        prev_hash = self._audit[-1]["chain_hash"] if self._audit else "genesis"
        fields = _audit_fields(tenant_id, user_id, jti, role, action, resource, detail, ts)
        chain = _chain_hash(prev_hash, fields)
        record = {
            "id": self._seq_audit,
            "seq": self._seq_audit,
            **fields,
            "chain_hash": chain,
            "prev_hash": prev_hash,
        }
        self._audit.append(record)
        return dict(record)

    async def list_audit(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
        since: float | None = None,
        until: float | None = None,
        cursor: int | None = None,
    ) -> list[dict[str, Any]]:
        rows = []
        for a in self._audit:
            if a["tenant_id"] != tenant_id:
                continue
            if since is not None and a["ts"] < since:
                continue
            if until is not None and a["ts"] > until:
                continue
            if cursor is not None and a["id"] <= cursor:
                continue
            rows.append(dict(a))
        rows.sort(key=lambda r: r["id"])
        return rows[-limit:] if limit < len(rows) else rows

    async def verify_audit_chain(self, tenant_id: str) -> dict[str, Any]:
        rows = [a for a in self._audit if a["tenant_id"] == tenant_id]
        rows.sort(key=lambda r: r["id"])
        prev = "genesis"
        for a in rows:
            expected = _chain_hash(
                prev,
                _audit_fields(
                    a["tenant_id"],
                    a["user_id"],
                    a["jti"],
                    a["role"],
                    a["action"],
                    a["resource"],
                    a["detail"],
                    a["ts"],
                ),
            )
            if not hmac.compare_digest(expected, a["chain_hash"]):
                return {"valid": False, "broken_at": a["id"]}
            prev = a["chain_hash"]
        return {"valid": True, "broken_at": None}

    async def revoke_jti(
        self,
        jti: str,
        *,
        tenant_id: str = "",
        user_id: str | None = None,
        reason: str = "admin_revoke",
        expires_at: float | None = None,
    ) -> None:
        self._revoked_jtis[jti] = {
            "jti": jti,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "reason": reason,
            "expires_at": expires_at or (_now() + 86400),
            "revoked_at": _now(),
        }
        logger.info("revoke_jti: %s reason=%s", jti, reason)

    async def is_jti_revoked(self, jti: str) -> bool:
        return jti in self._revoked_jtis

    async def insert_refresh_token(
        self,
        jti: str,
        family_id: str,
        tenant_id: str,
        user_id: str,
        expires_at: float,
        replaced_by: str | None = None,
        status: str = "active",
    ) -> dict[str, Any]:
        rec = {
            "jti": jti,
            "family_id": family_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "status": status,
            "issued_at": _now(),
            "expires_at": expires_at,
            "replaced_by": replaced_by,
        }
        self._refresh_tokens[jti] = rec
        return dict(rec)

    async def get_refresh_token(self, jti: str) -> dict[str, Any] | None:
        r = self._refresh_tokens.get(jti)
        return dict(r) if r else None

    async def rotate_refresh_token(self, old_jti: str, new_jti: str) -> bool:
        r = self._refresh_tokens.get(old_jti)
        if not r:
            return False
        r["status"] = "rotated"
        r["replaced_by"] = new_jti
        return True

    async def revoke_refresh_family(self, family_id: str) -> int:
        count = 0
        for r in self._refresh_tokens.values():
            if r["family_id"] == family_id and r["status"] != "revoked":
                r["status"] = "revoked"
                count += 1
        return count

    async def record_usage(
        self,
        tenant_id: str,
        user_id: str | None,
        metric: str,
        value: int,
        source: str,
        model: str | None = None,
    ) -> dict[str, Any]:
        ts = _now()
        rec = {
            "tenant_id": tenant_id,
            "user_id": user_id,
            "metric": metric,
            "value": value,
            "source": source,
            "model": model,
            "ts": ts,
        }
        self._usage.append(rec)
        logger.info(
            "record_usage: tenant=%s metric=%s value=%d source=%s model=%s",
            tenant_id,
            metric,
            value,
            source,
            model,
        )
        return dict(rec)

    async def aggregate_usage(
        self,
        tenant_id: str,
        since: float | None = None,
        until: float | None = None,
        metric: str | None = None,
    ) -> list[dict[str, Any]]:
        agg: dict[str, int] = {}
        for u in self._usage:
            if u["tenant_id"] != tenant_id:
                continue
            if since is not None and u["ts"] < since:
                continue
            if until is not None and u["ts"] > until:
                continue
            if metric is not None and u["metric"] != metric:
                continue
            agg[u["metric"]] = agg.get(u["metric"], 0) + u["value"]
        return [{"metric": m, "value": v} for m, v in sorted(agg.items())]

    async def stats(self) -> dict[str, Any]:
        return {
            "tenants": sum(1 for t in self._tenants.values() if t["status"] != "deleted"),
            "users": len(self._users),
            "members": len(self._members),
            "api_keys": sum(1 for k in self._api_keys.values() if not k["revoked_at"]),
            "audit_records": len(self._audit),
            "revoked_jtis": len(self._revoked_jtis),
            "refresh_tokens": sum(
                1 for r in self._refresh_tokens.values() if r["status"] == "active"
            ),
            "idps": len(self._idps),
            "mfa": len(self._mfa),
        }

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
    ) -> dict[str, Any]:
        if idp_id in self._idps:
            raise StoreConflict(f"idp {idp_id} exists")
        rec = {
            "idp_id": idp_id,
            "tenant_id": tenant_id,
            "type": type,
            "issuer_url": issuer_url,
            "client_id": client_id,
            "client_secret_enc": client_secret_enc,
            "scopes": scopes,
            "auto_provision": auto_provision,
            "created_at": _now(),
        }
        self._idps[idp_id] = rec
        logger.info("create_idp: %s tenant=%s type=%s", idp_id, tenant_id, type)
        return dict(rec)

    async def get_idp(self, idp_id: str) -> dict[str, Any] | None:
        r = self._idps.get(idp_id)
        return dict(r) if r else None

    async def list_idps(self, tenant_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._idps.values() if r["tenant_id"] == tenant_id]

    async def delete_idp(self, idp_id: str) -> bool:
        if idp_id not in self._idps:
            return False
        del self._idps[idp_id]
        logger.info("delete_idp: %s", idp_id)
        return True

    async def update_idp(self, idp_id: str, **fields: Any) -> dict[str, Any] | None:
        rec = self._idps.get(idp_id)
        if not rec:
            return None
        for k in (
            "type",
            "issuer_url",
            "client_id",
            "client_secret_enc",
            "scopes",
            "auto_provision",
        ):
            if k in fields and fields[k] is not None:
                rec[k] = fields[k]
        logger.info("update_idp: %s fields=%s", idp_id, list(fields))
        return dict(rec)

    async def upsert_mfa(
        self,
        user_id: str,
        method: str,
        *,
        secret_enc: str,
        enabled: bool = True,
    ) -> dict[str, Any]:
        key = (user_id, method)
        rec = {
            "user_id": user_id,
            "method": method,
            "secret_enc": secret_enc,
            "enrolled_at": self._mfa[key]["enrolled_at"] if key in self._mfa else _now(),
            "enabled": enabled,
        }
        self._mfa[key] = rec
        logger.info("upsert_mfa: user=%s method=%s enabled=%s", user_id, method, enabled)
        return dict(rec)

    async def get_mfa(self, user_id: str, method: str) -> dict[str, Any] | None:
        r = self._mfa.get((user_id, method))
        return dict(r) if r else None

    async def list_mfa(self, user_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._mfa.values() if r["user_id"] == user_id]

    async def delete_mfa(self, user_id: str, method: str) -> bool:
        key = (user_id, method)
        if key not in self._mfa:
            return False
        del self._mfa[key]
        logger.info("delete_mfa: user=%s method=%s", user_id, method)
        return True

    def get_mfa_sync(self, user_id: str, method: str) -> dict[str, Any] | None:
        r = self._mfa.get((user_id, method))
        return dict(r) if r else None


def _now() -> float:
    return time.time()
