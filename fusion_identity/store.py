from __future__ import annotations

import hashlib
import hmac
import logging
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
}


def scrypt_hash(password: str, salt: str = "fusion-identity") -> str:
    return hashlib.scrypt(
        password.encode(),
        salt=salt.encode(),
        n=16384,
        r=8,
        p=1,
        dklen=32,
    ).hex()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt = "fusion-identity"
        candidate = scrypt_hash(password, salt)
        return _const_eq(candidate, password_hash)
    except (ValueError, TypeError) as exc:
        logger.warning("verify_password failed: %s", exc)
        return False


def sha256_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _const_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class InMemoryStore:
    def __init__(self) -> None:
        self._tenants: dict[str, dict[str, Any]] = {}
        self._users: dict[str, dict[str, Any]] = {}
        self._members: dict[tuple[str, str], dict[str, Any]] = {}
        self._api_keys: dict[str, dict[str, Any]] = {}
        self._key_hash_index: dict[str, str] = {}
        self._quotas: dict[str, dict[str, Any]] = {}
        self._audit: list[dict[str, Any]] = []
        self._revoked_jtis: set[str] = set()
        self._roles = {k: dict(v) for k, v in ROLES_SEED.items()}
        self._seq_audit = 0
        logger.info("InMemoryStore initialized (roles seeded=%d)", len(self._roles))

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

    async def list_tenants(self) -> list[dict[str, Any]]:
        return [dict(t) for t in self._tenants.values() if t["status"] != "deleted"]

    async def update_tenant(self, tenant_id: str, **fields: Any) -> dict[str, Any] | None:
        t = self._tenants.get(tenant_id)
        if not t:
            return None
        for k in ("display_name", "status", "plan"):
            if k in fields:
                t[k] = fields[k]
        if t["status"] == "disabled" and not t["disabled_at"]:
            t["disabled_at"] = _now()
        return dict(t)

    async def delete_tenant(self, tenant_id: str) -> bool:
        t = self._tenants.get(tenant_id)
        if not t:
            return False
        t["status"] = "deleted"
        t["deleted_at"] = _now()
        return True

    async def create_user(
        self, user_id: str, username: str, password: str, email: str | None = None
    ) -> dict[str, Any]:
        if user_id in self._users:
            raise StoreConflict(f"user {user_id} exists")
        self._users[user_id] = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "password_hash": scrypt_hash(password),
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

    async def add_member(self, tenant_id: str, user_id: str, role: str) -> dict[str, Any]:
        if role not in ROLES_SEED:
            raise StoreConflict(f"unknown role {role}")
        key = (tenant_id, user_id)
        self._members[key] = {
            "tenant_id": tenant_id,
            "user_id": user_id,
            "role": role,
            "joined_at": _now(),
        }
        return dict(self._members[key])

    async def get_member(self, tenant_id: str, user_id: str) -> dict[str, Any] | None:
        m = self._members.get((tenant_id, user_id))
        return dict(m) if m else None

    async def get_member_role(self, tenant_id: str, user_id: str) -> str | None:
        m = self._members.get((tenant_id, user_id))
        return m["role"] if m else None

    async def list_members(self, tenant_id: str) -> list[dict[str, Any]]:
        return [dict(m) for (tid, _), m in self._members.items() if tid == tenant_id]

    async def remove_member(self, tenant_id: str, user_id: str) -> bool:
        return self._members.pop((tenant_id, user_id), None) is not None

    async def create_api_key(
        self, tenant_id: str, user_id: str | None, scopes: list[str]
    ) -> tuple[str, dict[str, Any]]:
        import secrets

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
        logger.info("create_api_key: %s tenant=%s", key_id, tenant_id)
        return raw, dict(record)

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
        for k in ("rpm", "tpm", "concurrent", "storage_mb", "allowed_models"):
            if k in fields:
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
        record = {
            "id": self._seq_audit,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "jti": jti,
            "role": role,
            "action": action,
            "resource": resource,
            "detail": detail,
            "chain_hash": _chain_hash(self._audit, detail),
            "ts": _now(),
        }
        self._audit.append(record)
        return dict(record)

    async def list_audit(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = [dict(a) for a in self._audit if a["tenant_id"] == tenant_id]
        return rows[-limit:]

    async def revoke_jti(self, jti: str) -> None:
        self._revoked_jtis.add(jti)
        logger.info("revoke_jti: %s", jti)

    async def is_jti_revoked(self, jti: str) -> bool:
        return jti in self._revoked_jtis


class StoreConflict(RuntimeError):
    pass


def _now() -> float:
    return time.time()


def _chain_hash(prev: list[dict[str, Any]], detail: Any) -> str:
    import json

    last = prev[-1]["chain_hash"] if prev else "genesis"
    payload = last + json.dumps(detail, default=str, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()
