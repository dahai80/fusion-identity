from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from fusion_identity.store import StoreConflict

logger = logging.getLogger(__name__)

try:
    import asyncpg
except ImportError:
    asyncpg = None


class StoreError(RuntimeError):
    pass


class PgStore:
    def __init__(self, database_url: str, pool_max: int = 8) -> None:
        if asyncpg is None:
            raise StoreError("asyncpg not installed; cannot use PgStore")
        self._database_url = database_url
        # P2-8: pool cap was hard-coded to 8, shared across all HTTP + gRPC
        # concurrent requests. Make it operator-configurable so a multi-node
        # gateway deployment can size the pool to its concurrency target.
        self._pool_max = max(1, int(pool_max))
        self._pool: Any = None

    async def connect(self) -> None:
        logger.info(
            "pgstore: connecting to %s pool_max=%s", _safe_url(self._database_url), self._pool_max
        )
        self._pool = await asyncpg.create_pool(
            dsn=self._database_url, min_size=1, max_size=self._pool_max
        )
        logger.info("pgstore: pool ready")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.info("pgstore: pool closed")

    async def _acquire(self):
        return self._pool.acquire()

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *args)
            return dict(row) if row is not None else None

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *args)
            return [dict(r) for r in rows]

    async def fetchval(self, sql: str, *args: Any) -> Any:
        async with self._pool.acquire() as conn:
            return await conn.fetchval(sql, *args)

    async def execute(self, sql: str, *args: Any) -> str:
        async with self._pool.acquire() as conn:
            return await conn.execute(sql, *args)

    async def ensure_schema(self) -> None:
        from fusion_identity.migrations import run_migrations

        if self._pool is None:
            logger.warning("pgstore.ensure_schema: pool not ready, skip migrations")
            return
        applied = await run_migrations(self._pool)
        logger.info("pgstore.ensure_schema: migrations applied=%s", applied)

    async def is_empty_tenants(self) -> bool:
        return await self.fetchval("SELECT COUNT(*) = 0 FROM tenants WHERE status <> 'deleted'")

    async def create_tenant(
        self, tenant_id: str, display_name: str, plan: str = "team"
    ) -> dict[str, Any]:
        try:
            row = await self.fetchrow(
                "INSERT INTO tenants(tenant_id, display_name, plan) VALUES ($1,$2,$3) RETURNING *",
                tenant_id,
                display_name,
                plan,
            )
        except asyncpg.UniqueViolationError as exc:
            raise StoreConflict(f"tenant {tenant_id} exists") from exc
        await self.fetchrow(
            "INSERT INTO quotas(tenant_id) VALUES ($1) ON CONFLICT DO NOTHING", tenant_id
        )
        return row

    async def get_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        return await self.fetchrow("SELECT * FROM tenants WHERE tenant_id=$1", tenant_id)

    async def get_tenant_status(self, tenant_id: str) -> str | None:
        return await self.fetchval("SELECT status FROM tenants WHERE tenant_id=$1", tenant_id)

    async def list_tenants(self) -> list[dict[str, Any]]:
        return await self.fetch(
            "SELECT * FROM tenants WHERE status <> 'deleted' ORDER BY created_at"
        )

    async def list_tenants_for(self, tenant_id: str) -> list[dict[str, Any]]:
        return await self.fetch(
            "SELECT * FROM tenants WHERE tenant_id=$1 AND status <> 'deleted'", tenant_id
        )

    async def update_tenant(self, tenant_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = ("display_name", "status", "plan")
        sets = [
            f"{k}=${i + 2}" for i, k in enumerate(allowed) if k in fields and fields[k] is not None
        ]
        if not sets:
            return await self.get_tenant(tenant_id)
        params: list[Any] = [tenant_id] + [
            fields[k] for k in allowed if k in fields and fields[k] is not None
        ]
        # F19: disabled_at CASE binds the status value, not $2 (which is display_name
        # when present). Compute a dedicated status param so the toggle is correct
        # regardless of which fields are set.
        status_val = fields.get("status")
        if status_val is not None:
            params.append(status_val)
            case_sql = (
                f"disabled_at=CASE WHEN ${len(params)}='disabled' "
                "THEN COALESCE(disabled_at, now()) ELSE NULL END"
            )
        else:
            case_sql = "disabled_at=disabled_at"
        sql = f"UPDATE tenants SET {', '.join(sets)}, {case_sql} WHERE tenant_id=$1 RETURNING *"
        return await self.fetchrow(sql, *params)

    async def delete_tenant(self, tenant_id: str) -> bool:
        val = await self.fetchval(
            "UPDATE tenants SET status='deleted', deleted_at=now() "
            "WHERE tenant_id=$1 AND status<>'deleted' RETURNING tenant_id",
            tenant_id,
        )
        if val is None:
            return False
        await self.execute(
            "UPDATE api_keys SET revoked_at=now() WHERE tenant_id=$1 AND revoked_at IS NULL",
            tenant_id,
        )
        await self.execute(
            "UPDATE refresh_tokens SET status='revoked' WHERE tenant_id=$1 AND status<>'revoked'",
            tenant_id,
        )
        await self.execute("DELETE FROM tenant_members WHERE tenant_id=$1", tenant_id)
        logger.info("delete_tenant: cascaded tenant=%s", tenant_id)
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
        from fusion_identity.store import hash_password

        pw_hash, salt, algo = hash_password(password)
        try:
            return await self.fetchrow(
                "INSERT INTO users(user_id, username, email, password_hash_v, "
                "salt, password_algo, must_change_password) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *",
                user_id,
                username,
                email,
                pw_hash,
                salt,
                algo,
                must_change_password,
            )
        except asyncpg.UniqueViolationError as exc:
            raise StoreConflict(f"user {user_id} exists") from exc

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        return await self.fetchrow("SELECT * FROM users WHERE username=$1", username)

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        return await self.fetchrow("SELECT * FROM users WHERE user_id=$1", user_id)

    async def get_user_status(self, user_id: str) -> str | None:
        return await self.fetchval("SELECT status FROM users WHERE user_id=$1", user_id)

    async def update_user(self, user_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = (
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
        )
        sets = []
        params: list[Any] = [user_id]
        idx = 2
        for k in allowed:
            if k in fields and fields[k] is not None:
                sets.append(f"{k}=${idx}")
                params.append(fields[k])
                idx += 1
        if not sets:
            return await self.get_user(user_id)
        sql = f"UPDATE users SET {', '.join(sets)} WHERE user_id=$1 RETURNING *"
        return await self.fetchrow(sql, *params)

    async def add_member(
        self,
        tenant_id: str,
        user_id: str,
        role: str,
        added_by: str | None = None,
    ) -> dict[str, Any]:
        try:
            return await self.fetchrow(
                "INSERT INTO tenant_members(tenant_id, user_id, role, added_by) "
                "VALUES ($1,$2,$3,$4) RETURNING *",
                tenant_id,
                user_id,
                role,
                added_by,
            )
        except asyncpg.UniqueViolationError as exc:
            raise StoreConflict(f"member {user_id} already in {tenant_id}") from exc

    async def get_member(self, tenant_id: str, user_id: str) -> dict[str, Any] | None:
        return await self.fetchrow(
            "SELECT * FROM tenant_members WHERE tenant_id=$1 AND user_id=$2", tenant_id, user_id
        )

    async def get_member_role(self, tenant_id: str, user_id: str) -> str | None:
        return await self.fetchval(
            "SELECT role FROM tenant_members WHERE tenant_id=$1 AND user_id=$2", tenant_id, user_id
        )

    async def update_member_role(
        self,
        tenant_id: str,
        user_id: str,
        role: str,
    ) -> dict[str, Any] | None:
        return await self.fetchrow(
            "UPDATE tenant_members SET role=$3 WHERE tenant_id=$1 AND user_id=$2 RETURNING *",
            tenant_id,
            user_id,
            role,
        )

    async def list_members(self, tenant_id: str) -> list[dict[str, Any]]:
        return await self.fetch(
            "SELECT * FROM tenant_members WHERE tenant_id=$1 ORDER BY joined_at", tenant_id
        )

    async def count_members_by_role(self, tenant_id: str, role: str) -> int:
        return await self.fetchval(
            "SELECT COUNT(*) FROM tenant_members WHERE tenant_id=$1 AND role=$2", tenant_id, role
        )

    async def remove_member(self, tenant_id: str, user_id: str) -> bool:
        val = await self.fetchval(
            "DELETE FROM tenant_members WHERE tenant_id=$1 AND user_id=$2 RETURNING user_id",
            tenant_id,
            user_id,
        )
        return val is not None

    async def create_api_key(
        self,
        tenant_id: str,
        user_id: str | None,
        scopes: list[str],
    ) -> tuple[str, dict[str, Any]]:
        import secrets as _s

        from fusion_identity.store import sha256_hash

        raw = "fmu_" + _s.token_urlsafe(24)
        key_id = "key_" + _s.token_hex(6)
        row = await self.fetchrow(
            "INSERT INTO api_keys(key_id, tenant_id, user_id, key_hash, prefix, scopes) "
            "VALUES ($1,$2,$3,$4,$5,$6::jsonb) RETURNING *",
            key_id,
            tenant_id,
            user_id,
            sha256_hash(raw),
            raw[:8] + "****",
            json.dumps(scopes),
        )
        return raw, row

    async def get_api_key_by_hash(self, key_hash: str) -> dict[str, Any] | None:
        row = await self.fetchrow(
            "SELECT * FROM api_keys WHERE key_hash=$1 AND revoked_at IS NULL", key_hash
        )
        return _decode_scopes(row) if row else None

    async def list_api_keys(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = await self.fetch(
            "SELECT * FROM api_keys WHERE tenant_id=$1 AND revoked_at IS NULL ORDER BY created_at",
            tenant_id,
        )
        return [_decode_scopes(r) for r in rows]

    async def revoke_api_key(self, key_id: str) -> bool:
        val = await self.fetchval(
            "UPDATE api_keys SET revoked_at=now() WHERE key_id=$1 "
            "AND revoked_at IS NULL RETURNING key_id",
            key_id,
        )
        return val is not None

    async def get_quota(self, tenant_id: str) -> dict[str, Any] | None:
        row = await self.fetchrow("SELECT * FROM quotas WHERE tenant_id=$1", tenant_id)
        return _decode_quota(row) if row else None

    async def put_quota(self, tenant_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = (
            "rpm",
            "tpm",
            "concurrent",
            "storage_mb",
            "allowed_models",
            "allowed_modules",
            "default_priority",
        )
        sets = ["updated_at=now()"]
        params: list[Any] = [tenant_id]
        idx = 2
        for k in allowed:
            if k in fields and fields[k] is not None:
                if k in ("allowed_models", "allowed_modules"):
                    sets.append(f"{k}=${idx}::jsonb")
                    params.append(json.dumps(fields[k]))
                else:
                    sets.append(f"{k}=${idx}")
                    params.append(fields[k])
                idx += 1
        sql = f"UPDATE quotas SET {', '.join(sets)} WHERE tenant_id=$1 RETURNING *"
        row = await self.fetchrow(sql, *params)
        return _decode_quota(row) if row else None

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
        from fusion_identity.store import _audit_fields, _chain_hash

        # F10: serialize per-tenant append under a transaction + advisory lock so
        # concurrent appends read the same prev_hash and chain without forking.
        async with self._pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", tenant_id)
            prev = (
                await conn.fetchval(
                    "SELECT chain_hash FROM audit_log WHERE tenant_id=$1 "
                    "ORDER BY seq DESC LIMIT 1 FOR UPDATE",
                    tenant_id,
                )
                or "genesis"
            )
            seq = await conn.fetchval("SELECT nextval('audit_seq_seq')")
            # F11: round ts to microsecond precision so TIMESTAMPTZ storage and the
            # float re-read in verify_audit_chain produce identical _chain_hash input.
            ts = round(time.time(), 6)
            fields = _audit_fields(tenant_id, user_id, jti, role, action, resource, detail, ts)
            chain = _chain_hash(prev, fields)
            row = await conn.fetchrow(
                "INSERT INTO audit_log(seq, tenant_id, user_id, jti, role, action, "
                "resource, detail, chain_hash, prev_hash, ts) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,to_timestamp($11)) RETURNING *",
                seq,
                tenant_id,
                user_id,
                jti,
                role,
                action,
                resource,
                json.dumps(detail, default=str),
                chain,
                prev,
                ts,
            )
            return dict(row)

    async def list_audit(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
        since: float | None = None,
        until: float | None = None,
        cursor: int | None = None,
    ) -> list[dict[str, Any]]:
        conds = ["tenant_id=$1"]
        params: list[Any] = [tenant_id]
        idx = 2
        if since is not None:
            conds.append(f"ts >= to_timestamp(${idx})")
            params.append(since)
            idx += 1
        if until is not None:
            conds.append(f"ts <= to_timestamp(${idx})")
            params.append(until)
            idx += 1
        if cursor is not None:
            conds.append(f"id < ${idx}")
            params.append(cursor)
            idx += 1
        params.append(limit)
        # F19: DESC newest-first, id < cursor — align with InMemory (newest window).
        sql = f"SELECT * FROM audit_log WHERE {' AND '.join(conds)} ORDER BY id DESC LIMIT ${idx}"
        return await self.fetch(sql, *params)

    async def verify_audit_chain(self, tenant_id: str) -> dict[str, Any]:
        import hmac as _hmac

        from fusion_identity.store import _audit_fields, _chain_hash

        rows = await self.fetch(
            "SELECT * FROM audit_log WHERE tenant_id=$1 ORDER BY id ASC", tenant_id
        )
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
                    a["ts"].timestamp(),
                ),
            )
            if not _hmac.compare_digest(expected, a["chain_hash"]):
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
        await self.execute(
            "INSERT INTO revoked_jtis(jti, tenant_id, user_id, reason, expires_at) "
            "VALUES ($1,$2,$3,$4,to_timestamp($5)) ON CONFLICT (jti) DO NOTHING",
            jti,
            tenant_id,
            user_id,
            reason,
            expires_at or (time.time() + 86400),
        )

    async def is_jti_revoked(self, jti: str) -> bool:
        return await self.fetchval("SELECT EXISTS(SELECT 1 FROM revoked_jtis WHERE jti=$1)", jti)

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
        return await self.fetchrow(
            "INSERT INTO refresh_tokens(jti, family_id, tenant_id, user_id, status, "
            "expires_at, replaced_by) "
            "VALUES ($1,$2,$3,$4,$5,to_timestamp($6),$7) RETURNING *",
            jti,
            family_id,
            tenant_id,
            user_id,
            status,
            expires_at,
            replaced_by,
        )

    async def get_refresh_token(self, jti: str) -> dict[str, Any] | None:
        row = await self.fetchrow("SELECT * FROM refresh_tokens WHERE jti=$1", jti)
        if row:
            row = dict(row)
            if row.get("expires_at"):
                row["expires_at"] = row["expires_at"].timestamp()
        return row

    async def rotate_refresh_token(self, old_jti: str, new_jti: str) -> bool:
        val = await self.fetchval(
            "UPDATE refresh_tokens SET status='rotated', replaced_by=$2 "
            "WHERE jti=$1 AND status='active' RETURNING jti",
            old_jti,
            new_jti,
        )
        return val is not None

    async def revoke_refresh_family(self, family_id: str) -> int:
        return await self.fetchval(
            "WITH u AS (UPDATE refresh_tokens SET status='revoked' "
            "WHERE family_id=$1 AND status<>'revoked' RETURNING 1) "
            "SELECT COUNT(*) FROM u",
            family_id,
        )

    async def record_issued_jti(self, jti: str, tenant_id: str, user_id: str) -> None:
        # F4: persist the (tenant, user) an access-token jti was issued to so
        # /revoke can assert ownership. ON CONFLICT refreshes expires_at in case
        # of a (vanishingly unlikely) jti collision.
        ttl_seconds = int(os.environ.get("FUSION_IDENTITY_JWT_TTL", "900"))
        await self.execute(
            "INSERT INTO issued_jtis (jti, tenant_id, user_id, expires_at) "
            "VALUES ($1,$2,$3, now() + ($4 || ' seconds')::interval) "
            "ON CONFLICT (jti) DO UPDATE SET expires_at = excluded.expires_at",
            jti,
            tenant_id,
            user_id,
            str(ttl_seconds),
        )

    async def get_jti_owner(self, jti: str) -> tuple[str, str | None] | None:
        # F4: resolve jti ownership from revoked_jtis, then issued_jtis (active
        # access tokens), then refresh_tokens.
        row = await self.fetchrow("SELECT tenant_id, user_id FROM revoked_jtis WHERE jti=$1", jti)
        if row and row.get("tenant_id"):
            return row["tenant_id"], row.get("user_id")
        row = await self.fetchrow("SELECT tenant_id, user_id FROM issued_jtis WHERE jti=$1", jti)
        if row:
            return row["tenant_id"], row.get("user_id")
        row = await self.fetchrow("SELECT tenant_id, user_id FROM refresh_tokens WHERE jti=$1", jti)
        if row:
            return row["tenant_id"], row.get("user_id")
        return None

    async def revoke_user_sessions(self, user_id: str) -> int:
        # L10: revoke all active refresh tokens for a user.
        return await self.fetchval(
            "WITH u AS (UPDATE refresh_tokens SET status='revoked' "
            "WHERE user_id=$1 AND status<>'revoked' RETURNING 1) "
            "SELECT COUNT(*) FROM u",
            user_id,
        )

    async def record_usage(
        self,
        tenant_id: str,
        user_id: str | None,
        metric: str,
        value: int,
        source: str,
        model: str | None = None,
    ) -> dict[str, Any]:
        await self.execute(
            "INSERT INTO usage_ledger"
            "(tenant_id, user_id, metric, value, source, model, bucket_hour) "
            "VALUES ($1,$2,$3,$4,$5,$6, date_trunc('hour', now())) "
            "ON CONFLICT (tenant_id, bucket_hour, metric, source, model) "
            "DO UPDATE SET value=usage_ledger.value+EXCLUDED.value",
            tenant_id,
            user_id,
            metric,
            value,
            source,
            model,
        )
        return {"tenant_id": tenant_id, "metric": metric, "value": value, "source": source}

    async def aggregate_usage(
        self,
        tenant_id: str,
        since: float | None = None,
        until: float | None = None,
        metric: str | None = None,
    ) -> list[dict[str, Any]]:
        conds = ["tenant_id=$1"]
        params: list[Any] = [tenant_id]
        idx = 2
        if since is not None:
            conds.append(f"bucket_hour >= to_timestamp(${idx})")
            params.append(since)
            idx += 1
        if until is not None:
            conds.append(f"bucket_hour <= to_timestamp(${idx})")
            params.append(until)
            idx += 1
        if metric is not None:
            conds.append(f"metric=${idx}")
            params.append(metric)
            idx += 1
        return await self.fetch(
            f"SELECT tenant_id, bucket_hour, metric, source, sum(value) as value "
            f"FROM usage_ledger WHERE {' AND '.join(conds)} "
            "GROUP BY tenant_id, bucket_hour, metric, source "
            "ORDER BY bucket_hour ASC",
            *params,
        )

    async def stats(self) -> dict[str, Any]:
        counts = {
            "tenants": "SELECT count(*) FROM tenants WHERE status <> 'deleted'",
            "users": "SELECT count(*) FROM users",
            "members": "SELECT count(*) FROM tenant_members",
            "api_keys": "SELECT count(*) FROM api_keys WHERE revoked_at IS NULL",
            "audit_records": "SELECT count(*) FROM audit_log",
            "revoked_jtis": "SELECT count(*) FROM revoked_jtis",
            "refresh_tokens": "SELECT count(*) FROM refresh_tokens WHERE status='active'",
            "idps": "SELECT count(*) FROM identity_providers",
            "mfa": "SELECT count(*) FROM user_mfa",
        }
        out: dict[str, Any] = {}
        for key, sql in counts.items():
            out[key] = await self.fetchval(sql)
        return out

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
        row = await self.fetchrow(
            """INSERT INTO identity_providers
               (idp_id, tenant_id, type, issuer_url, client_id, client_secret_enc,
                scopes, auto_provision)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
               RETURNING *""",
            idp_id,
            tenant_id,
            type,
            issuer_url,
            client_id,
            client_secret_enc,
            scopes,
            auto_provision,
        )
        logger.info("create_idp: %s tenant=%s", idp_id, tenant_id)
        return dict(row)

    async def get_idp(self, idp_id: str) -> dict[str, Any] | None:
        row = await self.fetchrow("SELECT * FROM identity_providers WHERE idp_id=$1", idp_id)
        return dict(row) if row else None

    async def list_idps(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = await self.fetch(
            "SELECT * FROM identity_providers WHERE tenant_id=$1 ORDER BY created_at", tenant_id
        )
        return [dict(r) for r in rows]

    async def delete_idp(self, idp_id: str) -> bool:
        status = await self.execute("DELETE FROM identity_providers WHERE idp_id=$1", idp_id)
        logger.info("delete_idp: %s status=%s", idp_id, status)
        return status.startswith("DELETE") and not status.endswith(" 0")

    async def update_idp(self, idp_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = (
            "type",
            "issuer_url",
            "client_id",
            "client_secret_enc",
            "scopes",
            "auto_provision",
        )
        sets: list[str] = []
        params: list[Any] = [idp_id]
        idx = 2
        for k in allowed:
            if k in fields and fields[k] is not None:
                sets.append(f"{k}=${idx}")
                params.append(fields[k])
                idx += 1
        if not sets:
            return await self.get_idp(idp_id)
        sql = f"UPDATE identity_providers SET {', '.join(sets)} WHERE idp_id=$1 RETURNING *"
        row = await self.fetchrow(sql, *params)
        return dict(row) if row else None

    async def upsert_mfa(
        self,
        user_id: str,
        method: str,
        *,
        secret_enc: str,
        enabled: bool = True,
    ) -> dict[str, Any]:
        row = await self.fetchrow(
            """INSERT INTO user_mfa (user_id, method, secret_enc, enabled)
               VALUES ($1,$2,$3,$4)
               ON CONFLICT (user_id, method)
               DO UPDATE SET secret_enc=EXCLUDED.secret_enc, enabled=EXCLUDED.enabled
               RETURNING *""",
            user_id,
            method,
            secret_enc,
            enabled,
        )
        logger.info("upsert_mfa: user=%s method=%s", user_id, method)
        return dict(row)

    async def get_mfa(self, user_id: str, method: str) -> dict[str, Any] | None:
        row = await self.fetchrow(
            "SELECT * FROM user_mfa WHERE user_id=$1 AND method=$2", user_id, method
        )
        return dict(row) if row else None

    async def list_mfa(self, user_id: str) -> list[dict[str, Any]]:
        rows = await self.fetch(
            "SELECT * FROM user_mfa WHERE user_id=$1 ORDER BY enrolled_at", user_id
        )
        return [dict(r) for r in rows]

    async def delete_mfa(self, user_id: str, method: str) -> bool:
        # F19: DELETE with RETURNING; plain fetchval returns None always.
        val = await self.fetchval(
            "DELETE FROM user_mfa WHERE user_id=$1 AND method=$2 RETURNING user_id",
            user_id,
            method,
        )
        return val is not None

    async def log_lease(
        self, tenant_id: str, lease_id: str, action: str, reason: str | None = None
    ) -> None:
        await self.execute(
            "INSERT INTO lease_log(tenant_id, lease_id, action, reason) VALUES ($1,$2,$3,$4)",
            tenant_id,
            lease_id,
            action,
            reason,
        )
        logger.debug("log_lease: tenant=%s lease=%s action=%s", tenant_id, lease_id, action)

    async def list_lease_log(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = await self.fetch(
            "SELECT * FROM lease_log WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2",
            tenant_id,
            limit,
        )
        return [dict(r) for r in rows]


def _decode_scopes(row: dict[str, Any]) -> dict[str, Any]:
    r = dict(row)
    if isinstance(r.get("scopes"), str):
        r["scopes"] = json.loads(r["scopes"])
    return r


def _decode_quota(row: dict[str, Any]) -> dict[str, Any]:
    r = dict(row)
    if isinstance(r.get("allowed_models"), str):
        r["allowed_models"] = json.loads(r["allowed_models"])
    if isinstance(r.get("allowed_modules"), str):
        r["allowed_modules"] = json.loads(r["allowed_modules"])
    return r


def _safe_url(url: str) -> str:
    if "@" in url:
        scheme, rest = url.split("://", 1)
        host = rest.split("@", 1)[1]
        return f"{scheme}://***@{host}"
    return url
