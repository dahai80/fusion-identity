from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from typing import Any

from fusion_identity.kdf import run_kdf

logger = logging.getLogger(__name__)

# P1-2: bounds so the default InMemoryStore does not leak memory unbounded on a
# long-running non-PgStore deployment. _issued_jtis are swept by TTL; the list
# stores are capped (oldest evicted) since they are append-only event logs.
_ISSUED_JTI_DEFAULT_TTL = 8 * 3600
_USAGE_CAP = 100000
_LEASE_LOG_CAP = 50000
_AUDIT_CAP = 100000

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

# Issue #40: how users may join a tenant. `invite` is the default for new
# tenants; the public community tenant is created with `open` (design
# decision 2, fusion-site-auth-1104 §4).
JOIN_POLICIES = frozenset({"invite", "proof", "approval", "open"})

DEFAULT_QUOTA = {
    "rpm": 60,
    "tpm": 100000,
    "concurrent": 4,
    "storage_mb": 10240,
    "allowed_models": [],
    "allowed_modules": [],
    "default_priority": 0,
}

# Issue #14 (M-C): named quota templates keyed by plan. `tpm` is the DAILY
# token limit (legacy field name, kept for compatibility). Effective quota on
# provisioning = template(plan) + per-tenant overrides. Admin-managed at
# runtime via PUT /api/v1/admin/plan-templates/{plan}.
PLAN_TEMPLATES = {
    "free": {
        "rpm": 10,
        "tpm": 20000,
        "concurrent": 2,
        "storage_mb": 1024,
        "allowed_models": [],
        "allowed_modules": [],
        "default_priority": 0,
    },
    "starter": {
        "rpm": 30,
        "tpm": 50000,
        "concurrent": 3,
        "storage_mb": 5120,
        "allowed_models": [],
        "allowed_modules": [],
        "default_priority": 0,
    },
    "standard": dict(DEFAULT_QUOTA),
    "pro": {
        "rpm": 200,
        "tpm": 1000000,
        "concurrent": 16,
        "storage_mb": 51200,
        "allowed_models": [],
        "allowed_modules": [],
        "default_priority": 1,
    },
    "enterprise": {
        "rpm": 1000,
        "tpm": 10000000,
        "concurrent": 64,
        "storage_mb": 204800,
        "allowed_models": [],
        "allowed_modules": [],
        "default_priority": 2,
    },
}

EVENT_STATUS_PENDING = "pending"
EVENT_STATUS_DELIVERED = "delivered"
EVENT_STATUS_DEAD = "dead"

LEGACY_SALT = "fusion-identity"
LOCK_THRESHOLD = 5
LOCK_DURATION_SECONDS = 15 * 60

# Issue #12 (E5): write classes derived deterministically from the built-in
# permission seeds — every resource with a "write" action becomes a write
# class the capability-spine mutation gating can intersect with.
WRITE_CLASSES = {
    role: sorted(f"{res}:write" for res, acts in seed["permissions"].items() if "write" in acts)
    for role, seed in ROLES_SEED.items()
}

# Issue #16 (Phase 2): identity-plane permission matrix for the built-in
# roles. Resources are identity's own tenant-scoped surfaces; actions are
# read (GET) / write (POST/PUT/PATCH) / delete (DELETE). The store is the
# role authority (issue #12) — deps.py consults this table, never the JWT
# role claim alone. tenant_admin is implicit-full and not listed.
BUILTIN_ROLE_MATRIX = {
    "operator": {
        "tenants": ("read",),
        "members": ("read",),
        "api_keys": ("read", "write", "delete"),
        "quotas": ("read",),
        "audit": ("read",),
        "usage": ("read",),
        "departments": ("read", "write", "delete"),
    },
    "member": {
        "tenants": ("read",),
        "usage": ("read",),
        "departments": ("read", "write"),
    },
    "viewer": {
        "tenants": ("read",),
        "quotas": ("read",),
        "usage": ("read",),
        "departments": ("read",),
    },
}

# Issue #12 (E5): default role <-> menu matrix rows for built-in roles. Menus
# themselves are declared by module manifests; identity only stores the matrix.
DEFAULT_ROLE_MENUS = {
    "tenant_admin": [
        "dashboard",
        "tenants",
        "users",
        "roles",
        "quotas",
        "usage",
        "audit",
        "settings",
    ],
    "operator": ["dashboard", "models", "tasks"],
    "member": ["dashboard", "tasks"],
    "viewer": ["dashboard", "models"],
}

# Bounds so a tenant_admin cannot balloon the RBAC policy unboundedly.
MAX_CUSTOM_ROLES_PER_TENANT = 64
MAX_WRITE_CLASSES_PER_ROLE = 64
MAX_MENUS_PER_TENANT = 256
MAX_MENUS_PER_ROLE = 64
_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")


def _valid_id(value: str) -> bool:
    return bool(_ID_PATTERN.match(value))


def _valid_write_classes(write_classes: list[str]) -> bool:
    if len(write_classes) > MAX_WRITE_CLASSES_PER_ROLE:
        return False
    return all(isinstance(w, str) and _valid_id(w) for w in write_classes)


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
        self._app_secrets: dict[str, dict[str, Any]] = {}
        self._app_credentials: dict[tuple[str, str], dict[str, Any]] = {}
        self._quotas: dict[str, dict[str, Any]] = {}
        self._audit: list[dict[str, Any]] = []
        self._revoked_jtis: dict[str, dict[str, Any]] = {}
        self._refresh_tokens: dict[str, dict[str, Any]] = {}
        self._issued_jtis: dict[str, tuple[str, str, float]] = {}
        self._roles = {k: dict(v) for k, v in ROLES_SEED.items()}
        self._seq_audit = 0
        self._usage: list[dict[str, Any]] = []
        self._idps: dict[str, dict[str, Any]] = {}
        self._mfa: dict[tuple[str, str], dict[str, Any]] = {}
        self._lease_log: list[dict[str, Any]] = []
        self._departments: dict[tuple[str, str], dict[str, Any]] = {}
        # Issue #74: prepaid orders + balance ledger (balance = SUM(delta),
        # no balance column to drift).
        self._prepaid_orders: dict[str, dict[str, Any]] = {}
        self._balance_ledger: list[dict[str, Any]] = []
        # Issue #12 (E5): per-tenant custom roles + runtime menu matrix.
        self._custom_roles: dict[tuple[str, str], dict[str, Any]] = {}
        self._menu_matrix: dict[tuple[str, str], list[str]] = {}
        self._known_menus: dict[str, list[str]] = {}
        # P1-2: per-tenant tail chain_hash so append_audit is O(1), not an O(n)
        # reverse scan every append (which made the whole audit append O(n²)).
        self._audit_tail_hash: dict[str, str] = {}
        # Issue #14: provisioning plane — plan templates, idempotency keys,
        # lifecycle event outbox.
        self._plan_templates: dict[str, dict[str, Any]] = {
            k: dict(v) for k, v in PLAN_TEMPLATES.items()
        }
        self._idempotency: dict[str, dict[str, Any]] = {}
        self._events: list[dict[str, Any]] = []
        self._event_seq = 0
        # Issue #40: join policy plane — invite tokens + join requests.
        self._invites: dict[str, dict[str, Any]] = {}
        self._sso_tickets: dict[str, dict[str, Any]] = {}
        self._join_requests: dict[str, dict[str, Any]] = {}
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
        self,
        tenant_id: str,
        display_name: str,
        plan: str = "team",
        join_policy: str = "invite",
    ) -> dict[str, Any]:
        if tenant_id in self._tenants:
            raise StoreConflict(f"tenant {tenant_id} exists")
        if join_policy not in JOIN_POLICIES:
            raise StoreConflict(f"unknown join_policy {join_policy!r}")
        now = _now()
        self._tenants[tenant_id] = {
            "tenant_id": tenant_id,
            "display_name": display_name,
            "status": "active",
            "plan": plan,
            "join_policy": join_policy,
            "created_at": now,
            "disabled_at": None,
            "deleted_at": None,
        }
        self._quotas[tenant_id] = {"tenant_id": tenant_id, "updated_at": now, **DEFAULT_QUOTA}
        logger.info("create_tenant: %s plan=%s join_policy=%s", tenant_id, plan, join_policy)
        return dict(self._tenants[tenant_id])

    async def set_join_policy(self, tenant_id: str, join_policy: str) -> dict[str, Any] | None:
        # Issue #40: admin-settable join policy (invite|proof|approval|open).
        if join_policy not in JOIN_POLICIES:
            raise StoreConflict(f"unknown join_policy {join_policy!r}")
        t = self._tenants.get(tenant_id)
        if t is None:
            return None
        t["join_policy"] = join_policy
        logger.info("set_join_policy: tenant=%s join_policy=%s", tenant_id, join_policy)
        return dict(t)

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
        jp = fields.get("join_policy")
        if jp is not None and jp not in JOIN_POLICIES:
            raise StoreConflict(f"unknown join_policy {jp!r}")
        for k in ("display_name", "status", "plan", "join_policy"):
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
        for key in [k for k in self._custom_roles if k[0] == tenant_id]:
            self._custom_roles.pop(key, None)
        for key in [k for k in self._menu_matrix if k[0] == tenant_id]:
            self._menu_matrix.pop(key, None)
        self._known_menus.pop(tenant_id, None)
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
        email_verified: bool = True,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        if user_id in self._users:
            raise StoreConflict(f"user {user_id} exists")
        # Issue #64: argon2 off the event loop (CPU-bound).
        pw_hash, salt, algo = await run_kdf(hash_password, password)
        self._users[user_id] = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "display_name": display_name,
            "password_hash": "",
            "password_hash_v": pw_hash,
            "salt": salt,
            "password_algo": algo,
            "status": "active",
            "failed_attempts": 0,
            "locked_until": None,
            "must_change_password": must_change_password,
            "last_login_at": None,
            # Issue #39: default TRUE — privileged creation paths (provision,
            # SCIM, members API) never block login; public signup sets False.
            "email_verified": email_verified,
            "email_verify_token_hash": None,
            "email_verify_expires": None,
            "created_at": _now(),
        }
        logger.info("create_user: %s username=%s", user_id, username)
        return dict(self._users[user_id])

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        for u in self._users.values():
            if u["username"] == username:
                return dict(u)
        return None

    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        # Issue #53: email lookup for duplicate-registration pre-check and the
        # password recovery plane. Case-insensitive — emails are not case
        # sensitive in practice and the UNIQUE column alone does not normalize.
        for u in self._users.values():
            if u.get("email") and u["email"].lower() == email.lower():
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

    async def set_email_verify_token(
        self, user_id: str, token_hash: str, expires_at: float
    ) -> bool:
        # Issue #39: (re)arm the verification token — the resend flow and the
        # initial signup both land here. Any previous token is invalidated by
        # overwrite.
        u = self._users.get(user_id)
        if u is None:
            return False
        u["email_verify_token_hash"] = token_hash
        u["email_verify_expires"] = expires_at
        logger.info("set_email_verify_token: user=%s", user_id)
        return True

    async def verify_email_token(self, token_hash: str) -> str | None:
        # Issue #39: single-use, expiring token redemption. Lookup is BY TOKEN
        # HASH (the verify endpoint carries no user id). Success marks the
        # account verified and clears the token so it cannot replay.
        for u in self._users.values():
            if u.get("email_verify_token_hash") != token_hash:
                continue
            expires = u.get("email_verify_expires")
            if expires is not None and expires < _now():
                logger.warning("verify_email_token: expired token user=%s", u["user_id"])
                return None
            u["email_verified"] = True
            u["email_verify_token_hash"] = None
            u["email_verify_expires"] = None
            logger.info("verify_email_token: verified user=%s", u["user_id"])
            return u["user_id"]
        return None

    async def set_password_reset_token(
        self, user_id: str, token_hash: str, expires_at: float
    ) -> bool:
        # Issue #54: (re)arm the password reset token. Overwrite invalidates
        # any previous token.
        u = self._users.get(user_id)
        if u is None:
            return False
        u["password_reset_token_hash"] = token_hash
        u["password_reset_expires"] = expires_at
        logger.info("set_password_reset_token: user=%s", user_id)
        return True

    async def consume_password_reset_token(self, token_hash: str) -> str | None:
        # Issue #54: single-use redemption — lookup by token hash, expiry
        # checked inline, columns cleared on success so the token cannot
        # replay.
        for u in self._users.values():
            if u.get("password_reset_token_hash") != token_hash:
                continue
            expires = u.get("password_reset_expires")
            if expires is not None and expires < _now():
                logger.warning("consume_password_reset_token: expired token user=%s", u["user_id"])
                return None
            u["password_reset_token_hash"] = None
            u["password_reset_expires"] = None
            logger.info("consume_password_reset_token: consumed user=%s", u["user_id"])
            return u["user_id"]
        return None

    async def add_member(
        self, tenant_id: str, user_id: str, role: str, added_by: str | None = None
    ) -> dict[str, Any]:
        if not await self.is_valid_role(tenant_id, role):
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

    async def memberships_for_user(self, user_id: str) -> list[dict[str, Any]]:
        # Issue #47: tenant resolution for tenant-less logins.
        out = []
        for tid, uid in self._members:
            if uid == user_id:
                m = self._members[(tid, uid)]
                out.append({"tenant_id": tid, "user_id": user_id, "role": m.get("role")})
        return out

    async def create_sso_ticket(
        self, ticket_hash: str, user_id: str, tenant_id: str, expires_at: float
    ) -> None:
        # Issue #48: one-time SSO ticket (hash at rest).
        self._sso_tickets[ticket_hash] = {
            "ticket_hash": ticket_hash,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "expires_at": expires_at,
            "used_at": None,
            "created_at": _now(),
        }

    async def consume_sso_ticket(self, ticket_hash: str) -> dict[str, Any] | None:
        rec = self._sso_tickets.get(ticket_hash)
        if rec is None:
            return None
        if rec["used_at"] is not None or rec["expires_at"] <= _now():
            return None
        rec["used_at"] = _now()
        return dict(rec)

    async def update_member_role(
        self, tenant_id: str, user_id: str, role: str
    ) -> dict[str, Any] | None:
        if not await self.is_valid_role(tenant_id, role):
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
        # P1-2: cap the lease log; oldest evicted from the front.
        if len(self._lease_log) > _LEASE_LOG_CAP:
            self._lease_log = self._lease_log[-_LEASE_LOG_CAP:]
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

    async def is_valid_role(self, tenant_id: str, role: str) -> bool:
        # Issue #12: a role id is valid if built-in or a custom role of THIS
        # tenant. Cross-tenant custom role reuse is denied.
        if role in ROLES_SEED:
            return True
        return (tenant_id, role) in self._custom_roles

    async def get_role(self, tenant_id: str, role_id: str) -> dict[str, Any] | None:
        if role_id in ROLES_SEED:
            return {
                "role_id": role_id,
                "tenant_id": tenant_id,
                "display_name": ROLES_SEED[role_id]["display_name"],
                "write_classes": list(WRITE_CLASSES[role_id]),
                "built_in": True,
                "menus": await self.get_role_menus(tenant_id, role_id),
            }
        rec = self._custom_roles.get((tenant_id, role_id))
        if rec is None:
            return None
        out = dict(rec)
        out["built_in"] = False
        out["menus"] = await self.get_role_menus(tenant_id, role_id)
        return out

    async def list_roles(self, tenant_id: str) -> list[dict[str, Any]]:
        roles = [await self.get_role(tenant_id, r) for r in ROLES_SEED]
        custom_ids = [rid for (tid, rid) in self._custom_roles if tid == tenant_id]
        roles += [await self.get_role(tenant_id, rid) for rid in custom_ids]
        return roles

    async def create_custom_role(
        self,
        tenant_id: str,
        role_id: str,
        display_name: str,
        write_classes: list[str],
    ) -> dict[str, Any]:
        if not _valid_id(role_id):
            raise StoreConflict(f"invalid role id {role_id!r}")
        if role_id in ROLES_SEED:
            raise StoreConflict(f"role {role_id} is built-in and immutable")
        tenant_custom = [k for k in self._custom_roles if k[0] == tenant_id]
        if len(tenant_custom) >= MAX_CUSTOM_ROLES_PER_TENANT:
            raise StoreConflict(f"custom role limit {MAX_CUSTOM_ROLES_PER_TENANT} reached")
        if not _valid_write_classes(write_classes):
            raise StoreConflict("invalid write_classes")
        key = (tenant_id, role_id)
        if key in self._custom_roles:
            raise StoreConflict(f"role {role_id} exists")
        now = _now()
        self._custom_roles[key] = {
            "role_id": role_id,
            "tenant_id": tenant_id,
            "display_name": display_name,
            "write_classes": list(write_classes),
            "created_at": now,
            "updated_at": now,
        }
        logger.info(
            "create_custom_role: role=%s tenant=%s wc=%d", role_id, tenant_id, len(write_classes)
        )
        return dict(self._custom_roles[key], built_in=False)

    async def update_custom_role(
        self,
        tenant_id: str,
        role_id: str,
        *,
        display_name: str | None = None,
        write_classes: list[str] | None = None,
    ) -> dict[str, Any] | None:
        if role_id in ROLES_SEED:
            raise StoreConflict(f"role {role_id} is built-in and immutable")
        rec = self._custom_roles.get((tenant_id, role_id))
        if rec is None:
            return None
        if display_name is not None:
            rec["display_name"] = display_name
        if write_classes is not None:
            if not _valid_write_classes(write_classes):
                raise StoreConflict("invalid write_classes")
            rec["write_classes"] = list(write_classes)
        rec["updated_at"] = _now()
        return dict(rec, built_in=False)

    async def delete_custom_role(self, tenant_id: str, role_id: str) -> bool:
        if role_id in ROLES_SEED:
            raise StoreConflict(f"role {role_id} is built-in and immutable")
        key = (tenant_id, role_id)
        if key not in self._custom_roles:
            return False
        in_use = sum(
            1 for (tid, _), m in self._members.items() if tid == tenant_id and m["role"] == role_id
        )
        if in_use:
            raise StoreConflict(f"role {role_id} still assigned to {in_use} member(s)")
        del self._custom_roles[key]
        self._menu_matrix.pop(key, None)
        logger.info("delete_custom_role: role=%s tenant=%s", role_id, tenant_id)
        return True

    async def set_role_menus(self, tenant_id: str, role_id: str, menus: list[str]) -> list[str]:
        if not await self.is_valid_role(tenant_id, role_id):
            raise StoreConflict(f"unknown role {role_id}")
        if len(menus) > MAX_MENUS_PER_ROLE:
            raise StoreConflict(f"menu limit {MAX_MENUS_PER_ROLE} per role")
        known = set(self._known_menus.get(tenant_id, [])) | {
            m for defaults in DEFAULT_ROLE_MENUS.values() for m in defaults
        }
        for m in menus:
            if not (isinstance(m, str) and _valid_id(m)):
                raise StoreConflict(f"invalid menu id {m!r}")
            if m not in known:
                raise StoreConflict(f"menu {m} not registered for tenant")
        self._menu_matrix[(tenant_id, role_id)] = list(dict.fromkeys(menus))
        logger.info("set_role_menus: role=%s tenant=%s menus=%d", role_id, tenant_id, len(menus))
        return list(self._menu_matrix[(tenant_id, role_id)])

    async def get_role_menus(self, tenant_id: str, role_id: str) -> list[str]:
        if (tenant_id, role_id) in self._menu_matrix:
            return list(self._menu_matrix[(tenant_id, role_id)])
        if role_id in DEFAULT_ROLE_MENUS:
            return list(DEFAULT_ROLE_MENUS[role_id])
        return []

    async def reset_role_menus(self, tenant_id: str, role_id: str) -> list[str]:
        if not await self.is_valid_role(tenant_id, role_id):
            raise StoreConflict(f"unknown role {role_id}")
        self._menu_matrix.pop((tenant_id, role_id), None)
        default = list(DEFAULT_ROLE_MENUS.get(role_id, []))
        logger.info("reset_role_menus: role=%s tenant=%s", role_id, tenant_id)
        return default

    async def add_known_menus(self, tenant_id: str, menus: list[str]) -> list[str]:
        if len(menus) > MAX_MENUS_PER_TENANT:
            raise StoreConflict(f"menu limit {MAX_MENUS_PER_TENANT} per tenant")
        current = list(self._known_menus.get(tenant_id, []))
        for m in menus:
            if not (isinstance(m, str) and _valid_id(m)):
                raise StoreConflict(f"invalid menu id {m!r}")
            if m not in current:
                current.append(m)
        if len(current) > MAX_MENUS_PER_TENANT:
            raise StoreConflict(f"menu limit {MAX_MENUS_PER_TENANT} per tenant")
        self._known_menus[tenant_id] = current
        logger.info("add_known_menus: tenant=%s total=%d", tenant_id, len(current))
        return list(current)

    async def list_known_menus(self, tenant_id: str) -> list[str]:
        return list(self._known_menus.get(tenant_id, []))

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

    # ------------------------------------------------------------------
    # Issue #74: prepaid balance & recharge. Orders move created -> paid
    # (idempotent); the first transition credits the balance ledger with
    # tokens + promo_tokens. Balance is always SUM(delta) over the ledger.
    # ------------------------------------------------------------------

    async def create_prepaid_order(
        self, tenant_id: str, tokens: int, promo_tokens: int, provider: str
    ) -> dict[str, Any]:
        order_id = "pre_" + secrets.token_hex(8)
        rec = {
            "order_id": order_id,
            "tenant_id": tenant_id,
            "tokens": tokens,
            "promo_tokens": promo_tokens,
            "status": "created",
            "provider": provider,
            "provider_ref": None,
            "created_at": _now(),
            "paid_at": None,
        }
        self._prepaid_orders[order_id] = rec
        logger.info(
            "create_prepaid_order: %s tenant=%s tokens=%d promo=%d provider=%s",
            order_id,
            tenant_id,
            tokens,
            promo_tokens,
            provider,
        )
        return dict(rec)

    async def get_prepaid_order(self, order_id: str) -> dict[str, Any] | None:
        rec = self._prepaid_orders.get(order_id)
        return dict(rec) if rec else None

    async def list_prepaid_orders(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = [o for o in self._prepaid_orders.values() if o["tenant_id"] == tenant_id]
        rows.sort(key=lambda o: o["created_at"], reverse=True)
        return [dict(o) for o in rows]

    async def count_paid_prepaid_orders(self, tenant_id: str) -> int:
        # Promo grants once per tenant: on the FIRST paid order.
        return sum(
            1
            for o in self._prepaid_orders.values()
            if o["tenant_id"] == tenant_id and o["status"] == "paid"
        )

    async def mark_prepaid_order_paid(
        self, order_id: str, provider_ref: str | None
    ) -> dict[str, Any] | None:
        rec = self._prepaid_orders.get(order_id)
        if not rec:
            return None
        if rec["status"] == "paid":
            logger.info("mark_prepaid_order_paid: %s already paid (idempotent replay)", order_id)
            return dict(rec)
        if rec["status"] != "created":
            logger.warning(
                "mark_prepaid_order_paid: %s in status=%s — refusing", order_id, rec["status"]
            )
            return None
        rec["status"] = "paid"
        rec["provider_ref"] = provider_ref
        rec["paid_at"] = _now()
        total = rec["tokens"] + rec["promo_tokens"]
        await self._append_ledger(rec["tenant_id"], total, "recharge", order_id)
        logger.info(
            "mark_prepaid_order_paid: %s tenant=%s credited=%d (tokens=%d promo=%d)",
            order_id,
            rec["tenant_id"],
            total,
            rec["tokens"],
            rec["promo_tokens"],
        )
        return dict(rec)

    async def _append_ledger(
        self, tenant_id: str, delta: int, reason: str, ref_id: str | None
    ) -> dict[str, Any]:
        entry = {
            "id": len(self._balance_ledger) + 1,
            "tenant_id": tenant_id,
            "delta": delta,
            "reason": reason,
            "ref_id": ref_id,
            "created_at": _now(),
        }
        self._balance_ledger.append(entry)
        return dict(entry)

    async def get_balance(self, tenant_id: str) -> int:
        return sum(e["delta"] for e in self._balance_ledger if e["tenant_id"] == tenant_id)

    async def debit_balance(self, tenant_id: str, tokens: int, ref_id: str | None) -> int:
        if tokens <= 0:
            return await self.get_balance(tenant_id)
        await self._append_ledger(tenant_id, -tokens, "consumption", ref_id)
        balance = await self.get_balance(tenant_id)
        logger.info(
            "debit_balance: tenant=%s tokens=%d ref=%s balance=%d",
            tenant_id,
            tokens,
            ref_id,
            balance,
        )
        return balance

    async def issue_app_secret(
        self, app_id: str, grace_seconds: int
    ) -> tuple[str, dict[str, Any], dict[str, Any] | None]:
        # Issue #28: application secret issuance for business apps (AGENTS.md
        # convention #1 — extra secrets come from identity, not .env stuffing).
        # Raw material is returned ONCE; only the sha256 hash is stored. Any
        # current version is demoted to grace so the app can decrypt-and-
        # re-encrypt during the window before the old version expires.
        now = _now()
        versions = [r["version"] for r in self._app_secrets.values() if r["app_id"] == app_id]
        version = max(versions) + 1 if versions else 1
        prev_current = None
        for rec in self._app_secrets.values():
            if rec["app_id"] == app_id and rec["status"] == "current":
                prev_current = rec
                break
        if prev_current is not None:
            prev_current["status"] = "grace"
            prev_current["grace_until"] = now + grace_seconds
        raw = "fms_" + secrets.token_urlsafe(32)
        secret_id = "sec_" + secrets.token_hex(6)
        record = {
            "secret_id": secret_id,
            "app_id": app_id,
            "version": version,
            "secret_hash": sha256_hash(raw),
            "prefix": raw[:8] + "****",
            "status": "current",
            "grace_until": None,
            "created_at": now,
        }
        self._app_secrets[secret_id] = record
        logger.info(
            "issue_app_secret: %s app=%s version=%d prev_demoted=%s",
            secret_id,
            app_id,
            version,
            prev_current["version"] if prev_current else None,
        )
        return (
            raw,
            dict(record),
            dict(prev_current) if prev_current is not None else None,
        )

    async def get_current_app_secret(self, app_id: str) -> dict[str, Any] | None:
        for rec in self._app_secrets.values():
            if rec["app_id"] == app_id and rec["status"] == "current":
                return dict(rec)
        return None

    async def has_app_secrets(self, app_id: str) -> bool:
        return any(r["app_id"] == app_id for r in self._app_secrets.values())

    async def list_app_secrets(self, app_id: str) -> list[dict[str, Any]]:
        now = _now()
        out = []
        for rec in self._app_secrets.values():
            if rec["app_id"] != app_id:
                continue
            item = {k: v for k, v in rec.items() if k != "secret_hash"}
            if (
                item["status"] == "grace"
                and item["grace_until"] is not None
                and item["grace_until"] < now
            ):
                item["status"] = "expired"
            out.append(item)
        out.sort(key=lambda r: r["version"], reverse=True)
        return out

    async def list_all_app_secrets(self) -> list[dict[str, Any]]:
        # Issue #35: cross-app inventory for the admin console key management
        # zone. Same shape as list_app_secrets (hash stripped, expired grace
        # normalized) but across every app_id.
        now = _now()
        out = []
        for rec in self._app_secrets.values():
            item = {k: v for k, v in rec.items() if k != "secret_hash"}
            if (
                item["status"] == "grace"
                and item["grace_until"] is not None
                and item["grace_until"] < now
            ):
                item["status"] = "expired"
            out.append(item)
        out.sort(key=lambda r: (r["app_id"], r["version"]), reverse=True)
        return out

    async def revoke_app_secret_version(self, app_id: str, version: int) -> dict[str, Any] | None:
        # Issue #35: immediate revocation of one version — cuts a grace window
        # short when a key is known compromised (UC-S3). Expired semantics stay
        # read-time for grace; revoked is a durable stored status.
        for rec in self._app_secrets.values():
            if rec["app_id"] == app_id and rec["version"] == version:
                rec["status"] = "revoked"
                rec["grace_until"] = None
                logger.info("revoke_app_secret_version: app=%s version=%d", app_id, version)
                return {k: v for k, v in rec.items() if k != "secret_hash"}
        return None

    async def get_member_summary(self, tenant_id: str) -> dict[str, Any]:
        # Issue #35: count-only member aggregate for the admin console member
        # zone — no usernames/emails leave the store.
        summary = {"total": 0, "active": 0, "disabled": 0, "locked": 0, "by_role": {}}
        for (tid, user_id), m in self._members.items():
            if tid != tenant_id:
                continue
            summary["total"] += 1
            user = self._users.get(user_id)
            status = user.get("status", "active") if user else "active"
            if status in summary:
                summary[status] += 1
            else:
                logger.warning(
                    "get_member_summary: unknown user status=%s user=%s", status, user_id
                )
            summary["by_role"][m["role"]] = summary["by_role"].get(m["role"], 0) + 1
        return summary

    async def get_idp_summary(self, tenant_id: str) -> dict[str, Any]:
        # Issue #35: SSO capability state for the admin console — types and
        # auto_provision flags only, never client_secret material.
        rows = [r for r in self._idps.values() if r["tenant_id"] == tenant_id]
        return {
            "configured": len(rows) > 0,
            "count": len(rows),
            "types": sorted({r["type"] for r in rows}),
            "auto_provision": any(r.get("auto_provision") for r in rows),
        }

    async def put_app_credential(self, app_id: str, name: str, secret_enc: str) -> dict[str, Any]:
        # Issue #34: store an externally-issued SaaS credential (already
        # KEK-encrypted by the route). Upsert by (app_id, name) — re-PUT is the
        # operator-side rotation path for third-party keys.
        now = _now()
        key = (app_id, name)
        rec = self._app_credentials.get(key)
        if rec is None:
            rec = {
                "app_id": app_id,
                "name": name,
                "secret_enc": secret_enc,
                "created_at": now,
                "updated_at": now,
                "fetch_count": 0,
                "last_fetched_at": None,
            }
            self._app_credentials[key] = rec
        else:
            rec["secret_enc"] = secret_enc
            rec["updated_at"] = now
        logger.info("put_app_credential: app=%s name=%s", app_id, name)
        return dict(rec)

    async def get_app_credential(self, app_id: str, name: str) -> dict[str, Any] | None:
        # Issue #34: fetch bumps the fetch counter + last_fetched_at so the
        # audit plane can spot anomaly patterns (mass 401 re-pulls).
        rec = self._app_credentials.get((app_id, name))
        if rec is None:
            return None
        rec["fetch_count"] = rec.get("fetch_count", 0) + 1
        rec["last_fetched_at"] = _now()
        logger.info(
            "get_app_credential: app=%s name=%s fetch_count=%d",
            app_id,
            name,
            rec["fetch_count"],
        )
        return dict(rec)

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

    # ------------------------------------------------------------------
    # Issue #14: provisioning plane — plan templates / idempotency / outbox
    # ------------------------------------------------------------------

    async def list_plan_templates(self) -> list[dict[str, Any]]:
        return [
            {"plan": plan, "quota": dict(q), "updated_at": None}
            for plan, q in self._plan_templates.items()
        ]

    async def get_plan_template(self, plan: str) -> dict[str, Any] | None:
        q = self._plan_templates.get(plan)
        return dict(q) if q else None

    async def put_plan_template(self, plan: str, quota: dict[str, Any]) -> dict[str, Any]:
        if not _valid_id(plan):
            raise StoreConflict(f"invalid plan id {plan!r}")
        merged = dict(self._plan_templates.get(plan, DEFAULT_QUOTA))
        for k in (
            "rpm",
            "tpm",
            "concurrent",
            "storage_mb",
            "allowed_models",
            "allowed_modules",
            "default_priority",
        ):
            if k in quota and quota[k] is not None:
                merged[k] = quota[k]
        self._plan_templates[plan] = merged
        logger.info("put_plan_template: plan=%s", plan)
        return dict(merged)

    async def get_idempotency(self, idem_key: str) -> dict[str, Any] | None:
        rec = self._idempotency.get(idem_key)
        return dict(rec) if rec else None

    async def put_idempotency(self, idem_key: str, endpoint: str, response: dict[str, Any]) -> None:
        self._idempotency[idem_key] = {
            "idem_key": idem_key,
            "endpoint": endpoint,
            "response": response,
            "created_at": _now(),
        }
        logger.info("put_idempotency: key=%s endpoint=%s", idem_key, endpoint)

    # --- Issue #40: join policy plane (invites + join requests) ---

    async def create_invite(
        self,
        invite_id: str,
        tenant_id: str,
        token_hash: str,
        role: str,
        expires_at: float,
        email: str | None = None,
        created_by: str | None = None,
    ) -> dict[str, Any]:
        if not await self.is_valid_role(tenant_id, role):
            raise StoreConflict(f"unknown role {role} for tenant {tenant_id}")
        rec = {
            "invite_id": invite_id,
            "tenant_id": tenant_id,
            "token_hash": token_hash,
            "role": role,
            "email": email,
            "created_by": created_by,
            "expires_at": expires_at,
            "used_at": None,
            "used_by": None,
            "created_at": _now(),
        }
        self._invites[invite_id] = rec
        logger.info("create_invite: tenant=%s invite=%s role=%s", tenant_id, invite_id, role)
        return dict(rec)

    async def get_invite_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        for rec in self._invites.values():
            if rec["token_hash"] == token_hash:
                return dict(rec)
        return None

    async def list_invites(self, tenant_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._invites.values() if r["tenant_id"] == tenant_id]

    async def mark_invite_used(self, invite_id: str, user_id: str) -> bool:
        rec = self._invites.get(invite_id)
        if rec is None or rec["used_at"] is not None:
            return False
        rec["used_at"] = _now()
        rec["used_by"] = user_id
        logger.info("mark_invite_used: invite=%s user=%s", invite_id, user_id)
        return True

    async def create_join_request(
        self, request_id: str, tenant_id: str, user_id: str
    ) -> dict[str, Any]:
        for r in self._join_requests.values():
            if r["tenant_id"] == tenant_id and r["user_id"] == user_id and r["status"] == "pending":
                raise StoreConflict("join request already pending")
        rec = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "status": "pending",
            "decided_by": None,
            "decided_at": None,
            "created_at": _now(),
        }
        self._join_requests[request_id] = rec
        logger.info("create_join_request: tenant=%s user=%s", tenant_id, user_id)
        return dict(rec)

    async def get_join_request(self, request_id: str) -> dict[str, Any] | None:
        r = self._join_requests.get(request_id)
        return dict(r) if r else None

    async def list_join_requests(
        self, tenant_id: str, status: str | None = None
    ) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self._join_requests.values()
            if r["tenant_id"] == tenant_id and (status is None or r["status"] == status)
        ]

    async def decide_join_request(
        self, request_id: str, status: str, decided_by: str
    ) -> dict[str, Any] | None:
        # status is the DECISION: approved | rejected (also cancelled by the
        # requester). Only a pending request can be decided.
        if status not in ("approved", "rejected", "cancelled"):
            raise StoreConflict(f"invalid decision status {status!r}")
        r = self._join_requests.get(request_id)
        if r is None:
            return None
        if r["status"] != "pending":
            raise StoreConflict(f"join request already {r['status']}")
        r["status"] = status
        r["decided_by"] = decided_by
        r["decided_at"] = _now()
        logger.info("decide_join_request: request=%s status=%s", request_id, status)
        return dict(r)

    async def append_event(
        self, event_type: str, tenant_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        self._event_seq += 1
        event_id = "evt_" + secrets.token_hex(8)
        rec = {
            "event_id": event_id,
            "seq": self._event_seq,
            "event_type": event_type,
            "tenant_id": tenant_id,
            "payload": payload,
            "status": EVENT_STATUS_PENDING,
            "attempts": 0,
            "created_at": _now(),
            "updated_at": _now(),
        }
        self._events.append(rec)
        # P1-2: cap the outbox; oldest evicted from the front.
        if len(self._events) > _AUDIT_CAP:
            self._events = self._events[-_AUDIT_CAP:]
        logger.info("append_event: %s tenant=%s seq=%d", event_type, tenant_id, rec["seq"])
        return dict(rec)

    async def list_events(self, cursor: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        return [dict(e) for e in self._events if e["seq"] > cursor][:limit]

    async def pending_events(self, limit: int = 20) -> list[dict[str, Any]]:
        return [dict(e) for e in self._events if e["status"] == EVENT_STATUS_PENDING][:limit]

    async def mark_event(self, event_id: str, status: str, attempts: int | None = None) -> bool:
        for e in self._events:
            if e["event_id"] == event_id:
                e["status"] = status
                if attempts is not None:
                    e["attempts"] = attempts
                e["updated_at"] = _now()
                return True
        return False

    async def create_department(
        self,
        tenant_id: str,
        name: str,
        *,
        parent_id: str | None = None,
        tool_allowlist: list[str] | None = None,
    ) -> dict[str, Any]:
        # Issue #10: department structure + per-department tool permission
        # profile consumed by admin consoles (e.g. fusion-cowork).
        dept_id = "dept_" + secrets.token_hex(6)
        rec = {
            "dept_id": dept_id,
            "tenant_id": tenant_id,
            "name": name,
            "parent_id": parent_id,
            "tool_allowlist": list(tool_allowlist or []),
            "created_at": _now(),
            "updated_at": _now(),
        }
        self._departments[(tenant_id, dept_id)] = rec
        logger.info("create_department: %s tenant=%s", dept_id, tenant_id)
        return dict(rec)

    async def get_department(self, tenant_id: str, dept_id: str) -> dict[str, Any] | None:
        d = self._departments.get((tenant_id, dept_id))
        return dict(d) if d else None

    async def list_departments(self, tenant_id: str) -> list[dict[str, Any]]:
        return [dict(d) for d in self._departments.values() if d["tenant_id"] == tenant_id]

    async def update_department(
        self, tenant_id: str, dept_id: str, **fields: Any
    ) -> dict[str, Any] | None:
        d = self._departments.get((tenant_id, dept_id))
        if not d:
            return None
        for k in ("name", "parent_id", "tool_allowlist"):
            if k in fields and fields[k] is not None:
                d[k] = fields[k]
        d["updated_at"] = _now()
        logger.info("update_department: %s tenant=%s", dept_id, tenant_id)
        return dict(d)

    async def delete_department(self, tenant_id: str, dept_id: str) -> bool:
        removed = self._departments.pop((tenant_id, dept_id), None) is not None
        if removed:
            logger.info("delete_department: %s tenant=%s", dept_id, tenant_id)
        return removed

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
        # F11: round to microsecond precision so verify_audit_chain re-reads an
        # identical ts (PgStore stores TIMESTAMPTZ at microsecond precision).
        ts = round(_now(), 6)
        # F12: prev_hash is per-tenant (last record of the SAME tenant), not the
        # global last record — matches PgStore WHERE tenant_id=$1 ordering.
        # P1-2: O(1) lookup via a per-tenant tail-hash index instead of an O(n)
        # reverse scan every append (which made audit append O(n²) over time).
        prev_hash = self._audit_tail_hash.get(tenant_id, "genesis")
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
        self._audit_tail_hash[tenant_id] = chain
        # P1-2: cap the audit log; evict oldest from the front. The tail index
        # points at each tenant's MOST RECENT record, which is never the evicted
        # front record, so the per-tenant chain stays intact.
        if len(self._audit) > _AUDIT_CAP:
            self._audit = self._audit[-_AUDIT_CAP:]
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
            if cursor is not None and a["id"] >= cursor:
                continue
            rows.append(dict(a))
        # F19: newest-first (DESC by id) to match PgStore list_audit.
        rows.sort(key=lambda r: r["id"], reverse=True)
        return rows[:limit]

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
        # P7: sweep expired jti entries so _revoked_jtis does not grow unbounded.
        now = _now()
        expired = [j for j, r in self._revoked_jtis.items() if r["expires_at"] < now]
        for j in expired:
            self._revoked_jtis.pop(j, None)
            logger.debug("sweep revoked jti expired: %s", j)
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
        # F7 CAS: only an 'active' token can rotate. A 'rotated'/'revoked'
        # token means a concurrent refresh already won — return False so the
        # caller enters the reuse path (revoke family + refuse).
        if not r or r["status"] != "active":
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

    async def record_issued_jti(self, jti: str, tenant_id: str, user_id: str) -> None:
        # F4: record the (tenant, user) that an issued access-token jti belongs
        # to, so /revoke can assert ownership before revoking an active token.
        # P1-2: store an expiry so _issued_jtis can be swept (it grew unbounded
        # before — asymmetric with the swept _revoked_jtis). TTL defaults to the
        # max access-token lifetime; the store has no settings handle, so a
        # module default is used (operators on PgStore are unaffected).
        self._sweep_issued_jtis()
        self._issued_jtis[jti] = (tenant_id, user_id, _now() + _ISSUED_JTI_DEFAULT_TTL)

    def _sweep_issued_jtis(self) -> None:
        # P1-2: opportunistic sweep of expired issued-jti entries.
        now = _now()
        expired = [j for j, rec in self._issued_jtis.items() if rec[2] < now]
        for j in expired:
            self._issued_jtis.pop(j, None)
            logger.debug("sweep issued jti expired: %s", j)

    async def get_jti_owner(self, jti: str) -> tuple[str, str | None] | None:
        # F4: resolve which tenant/user owns a jti. Order: revoked-jti ledger
        # (post-revoke), issued-jti ledger (active access tokens), then active
        # refresh tokens. Returns (tenant_id, user_id) or None if unknown.
        rec = self._revoked_jtis.get(jti)
        if rec and rec.get("tenant_id"):
            return rec["tenant_id"], rec.get("user_id")
        # P3-4: only an unexpired issued jti counts as an active owner.
        issued = self._issued_jtis.get(jti)
        if issued is not None and issued[2] >= _now():
            return issued[0], issued[1]
        for r in self._refresh_tokens.values():
            if r["jti"] == jti:
                return r["tenant_id"], r["user_id"]
        return None

    async def revoke_user_sessions(self, user_id: str) -> int:
        # L10: revoke every active refresh token family for a user (password
        # change / forced logout). Access-token jtis are short-lived and
        # validated against membership on every call, so revoking refresh
        # families + recording the user's sessions as revoked is sufficient.
        count = 0
        seen_families: set[str] = set()
        for r in self._refresh_tokens.values():
            if r["user_id"] == user_id and r["status"] != "revoked":
                if r["family_id"] not in seen_families:
                    seen_families.add(r["family_id"])
                r["status"] = "revoked"
                count += 1
        logger.info("revoke_user_sessions: user=%s revoked=%d refresh tokens", user_id, count)
        return count

    async def revoke_user_issued_jtis(
        self,
        user_id: str,
        tenant_id: str | None = None,
        reason: str = "user_deletion",
    ) -> int:
        # Issue #29: put every unexpired issued jti (access + session tokens)
        # of the user onto the revocation ledger. verify_token and
        # verify_session_token both consult revoked_jtis, so this is what
        # actually kills live tokens — refresh-family revocation alone leaves
        # the current access/session token valid until natural expiry.
        now = _now()
        count = 0
        for jti, (tid, uid, expires_at) in list(self._issued_jtis.items()):
            if uid != user_id:
                continue
            if tenant_id is not None and tid != tenant_id:
                continue
            if expires_at <= now:
                continue
            if jti in self._revoked_jtis:
                continue
            await self.revoke_jti(
                jti, tenant_id=tid, user_id=uid, reason=reason, expires_at=expires_at
            )
            count += 1
        logger.info(
            "revoke_user_issued_jtis: user=%s tenant=%s revoked=%d reason=%s",
            user_id,
            tenant_id,
            count,
            reason,
        )
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
        # P1-2: cap usage log so a long-running InMemoryStore does not grow
        # unbounded. aggregate_usage scans the full list, so the cap also bounds
        # that scan. Oldest rows evicted from the front.
        if len(self._usage) > _USAGE_CAP:
            self._usage = self._usage[-_USAGE_CAP:]
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

    async def usage_summary(
        self,
        tenant_id: str,
        *,
        since: float | None = None,
        until: float | None = None,
    ) -> dict[str, Any]:
        # Issue #10: aggregated usage report (totals per metric/source/model)
        # for enterprise admin consoles.
        totals: dict[str, int] = {}
        by_source: dict[str, int] = {}
        by_model: dict[str, int] = {}
        events = 0
        for u in self._usage:
            if u["tenant_id"] != tenant_id:
                continue
            if since is not None and u["ts"] < since:
                continue
            if until is not None and u["ts"] > until:
                continue
            value = int(u.get("value", 0))
            totals[u["metric"]] = totals.get(u["metric"], 0) + value
            src = u.get("source") or "unknown"
            by_source[src] = by_source.get(src, 0) + value
            model = u.get("model") or "unspecified"
            by_model[model] = by_model.get(model, 0) + value
            events += 1
        return {
            "events": events,
            "totals": totals,
            "by_source": by_source,
            "by_model": by_model,
        }

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
            # P1-5: surface dormant legacy-scrypt accounts (fixed salt, never
            # rehashed because they never log in). A DB leak exposes them to a
            # single precomputed rainbow table. >0 → operator force-resets.
            "legacy_scrypt_users": sum(
                1 for u in self._users.values() if (u.get("password_algo") or "") == "scrypt"
            ),
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

    async def list_all_idps(self) -> list[dict[str, Any]]:
        # D2: cross-tenant sweep for the KEK re-encrypt rotation. Runs under the
        # _system scope (admin, service-token gated) so every IdP secret is seen.
        return [dict(r) for r in self._idps.values() if r.get("client_secret_enc")]

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

    async def list_all_mfa(self) -> list[dict[str, Any]]:
        # D2: cross-tenant sweep for the KEK re-encrypt rotation. Returns every
        # enrolled MFA factor with a stored secret so the sweep can re-encrypt it.
        return [dict(r) for r in self._mfa.values() if r.get("secret_enc")]

    async def delete_mfa(self, user_id: str, method: str) -> bool:
        key = (user_id, method)
        if key not in self._mfa:
            return False
        del self._mfa[key]
        logger.info("delete_mfa: user=%s method=%s", user_id, method)
        return True


def _now() -> float:
    return time.time()
