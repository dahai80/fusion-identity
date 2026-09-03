from __future__ import annotations

import logging
import os
import uuid

import pytest

logger = logging.getLogger(__name__)

PG_URL = os.environ.get("FUSION_IDENTITY_DATABASE_URL", "postgresql://127.0.0.1:5432/fusion_tenant")
# The low-priv role created by migration 0007. The operator may rotate its
# password; the test falls back to the migration default when this env is unset.
APP_ROLE_URL = os.environ.get(
    "FUSION_IDENTITY_APP_ROLE_URL",
    "postgresql://fusion_identity_app:change-me-operator-rotates@127.0.0.1:5432/fusion_tenant",
)

pytestmark = pytest.mark.integration

TENANT_SCOPED_TABLES = [
    "tenants",
    "tenant_members",
    "api_keys",
    "quotas",
    "usage_ledger",
    "tenant_usage_daily",
    "refresh_tokens",
    "revoked_jtis",
    "issued_jtis",
    "audit_log",
    "identity_providers",
    "lease_log",
]


async def _admin_conn():
    import asyncpg

    return await asyncpg.connect(PG_URL)


async def _app_conn():
    import asyncpg

    return await asyncpg.connect(APP_ROLE_URL)


async def _seed_two_tenants(admin, sufix):
    ta = "rls_" + sufix + "_a"
    tb = "rls_" + sufix + "_b"
    for tid in (ta, tb):
        await admin.execute(
            "INSERT INTO tenants(tenant_id, display_name) VALUES ($1,$2) "
            "ON CONFLICT (tenant_id) DO NOTHING",
            tid,
            tid,
        )
        await admin.execute("INSERT INTO quotas(tenant_id) VALUES ($1) ON CONFLICT DO NOTHING", tid)
        await admin.execute(
            "INSERT INTO api_keys(key_id, tenant_id, key_hash, prefix, scopes) "
            "VALUES ($1,$2,$3,$4,'[]'::jsonb) ON CONFLICT (key_id) DO NOTHING",
            "key_" + tid,
            tid,
            "hash_" + tid,
            tid[:8] + "****",
        )
    return ta, tb


async def _cleanup_tenants(admin, tids):
    import contextlib

    for tid in tids:
        for sql in (
            "DELETE FROM audit_log WHERE tenant_id=$1",
            "DELETE FROM api_keys WHERE tenant_id=$1",
            "DELETE FROM quotas WHERE tenant_id=$1",
            "DELETE FROM tenants WHERE tenant_id=$1",
        ):
            with contextlib.suppress(Exception):
                await admin.execute(sql, tid)


async def test_rls_enforced_on_all_tenant_scoped_tables():
    # Every tenant-scoped table must have RLS enabled and forced so even the
    # table owner is subject to the policy.
    admin = await _admin_conn()
    try:
        rows = await admin.fetch(
            "SELECT relname, relrowsecurity, relforcerowsecurity "
            "FROM pg_class WHERE relname = ANY($1::text[])",
            TENANT_SCOPED_TABLES,
        )
        by_name = {r["relname"]: r for r in rows}
        assert set(by_name) == set(TENANT_SCOPED_TABLES), (
            f"missing RLS metadata for: {set(TENANT_SCOPED_TABLES) - set(by_name)}"
        )
        for name in TENANT_SCOPED_TABLES:
            assert by_name[name]["relrowsecurity"], f"{name} RLS not enabled"
            assert by_name[name]["relforcerowsecurity"], f"{name} RLS not forced"
    finally:
        await admin.close()


async def test_system_guc_sees_all_tenants():
    # Default GUC '_system' (set at DB level by 0007) lets the low-priv role
    # see every tenant — the platform/admin sentinel. A connection that never
    # narrows the GUC must NOT be silently fenced out.
    admin = await _admin_conn()
    sufix = uuid.uuid4().hex[:8]
    ta, tb = await _seed_two_tenants(admin, sufix)
    app = await _app_conn()
    try:
        tenants = [r["tenant_id"] for r in await app.fetch("SELECT tenant_id FROM tenants")]
        assert ta in tenants and tb in tenants, f"_system must see both tenants, got {tenants}"
    finally:
        await app.close()
        await _cleanup_tenants(admin, (ta, tb))
        await admin.close()


async def test_tenant_guc_fences_to_own_tenant():
    # Narrowing app.current_tenant to tenant A hides tenant B's rows across
    # every tenant-scoped table. This is the strong-layer guarantee: even a
    # query with no WHERE tenant_id filter is fenced by RLS.
    admin = await _admin_conn()
    sufix = uuid.uuid4().hex[:8]
    ta, tb = await _seed_two_tenants(admin, sufix)
    app = await _app_conn()
    try:
        await app.execute("SELECT set_config('app.current_tenant', $1, false)", ta)
        tenants = [r["tenant_id"] for r in await app.fetch("SELECT tenant_id FROM tenants")]
        assert tenants == [ta], f"tenant A must see only itself, got {tenants}"
        assert tb not in tenants, "tenant B leaked under GUC=A"
        # api_keys / audit_log: filtered without an explicit WHERE.
        keys = [r["tenant_id"] for r in await app.fetch("SELECT tenant_id FROM api_keys")]
        assert keys == [ta], f"api_keys leaked cross-tenant under GUC=A, got {keys}"
        quotas = [r["tenant_id"] for r in await app.fetch("SELECT tenant_id FROM quotas")]
        assert quotas == [ta], f"quotas leaked cross-tenant under GUC=A, got {quotas}"
        # A row insert tagged to tenant B must be rejected by WITH CHECK.
        import asyncpg

        with pytest.raises(asyncpg.PostgresError):
            await app.execute(
                "INSERT INTO api_keys(key_id, tenant_id, key_hash, prefix, scopes) "
                "VALUES ($1,$2,$3,$4,'[]'::jsonb)",
                "key_cross_" + sufix,
                tb,
                "h_cross",
                "cross****",
            )
    finally:
        await app.close()
        await _cleanup_tenants(admin, (ta, tb))
        await admin.close()


async def test_superuser_bypasses_rls_but_app_role_does_not():
    # Confirms the threat model: the operator's superuser account bypasses RLS
    # (so RLS cannot break operator tooling), while the dedicated app role is
    # the one that actually enforces it. Documents why fusion_identity_app is
    # the production connection role.
    admin = await _admin_conn()
    sufix = uuid.uuid4().hex[:8]
    ta, tb = await _seed_two_tenants(admin, sufix)
    app = await _app_conn()
    try:
        # Superuser sees both even with GUC narrowed (BYPASSRLS by superuser rule).
        await admin.execute("SELECT set_config('app.current_tenant', $1, false)", ta)
        su_tenants = [r["tenant_id"] for r in await admin.fetch("SELECT tenant_id FROM tenants")]
        assert {ta, tb}.issubset(set(su_tenants)), "superuser should bypass RLS"
        # App role under the same narrow GUC sees only A.
        await app.execute("SELECT set_config('app.current_tenant', $1, false)", ta)
        app_tenants = [r["tenant_id"] for r in await app.fetch("SELECT tenant_id FROM tenants")]
        assert app_tenants == [ta], f"app role must be fenced, got {app_tenants}"
    finally:
        await app.close()
        await _cleanup_tenants(admin, (ta, tb))
        await admin.close()


async def test_pgstore_guc_narrows_from_tenant_context():
    # D1: the production code path. PgStore reads the fusion_core TenantContext
    # contextvar and narrows app.current_tenant per acquire so the strong RLS
    # layer actually enforces per-request. An app-role PgStore under tenant A's
    # context must see only tenant A; a cross-tenant insert via the store must
    # be rejected by WITH CHECK. No context → _system sees all.
    import contextlib

    from fusion_core.tenant.context import TenantContext, reset, set_context

    from fusion_identity.db import PgStore

    admin = await _admin_conn()
    sufix = uuid.uuid4().hex[:8]
    ta, tb = await _seed_two_tenants(admin, sufix)
    store = PgStore(APP_ROLE_URL, pool_max=2)
    await store.connect()
    try:
        # No context → _system → sees both tenants (platform/login scope).
        both = [r["tenant_id"] for r in await store.fetch("SELECT tenant_id FROM tenants")]
        assert ta in both and tb in both, f"_system must see both, got {both}"

        # Narrow to tenant A via the same contextvar the HTTP middleware sets.
        tok = set_context(TenantContext(tenant_id=ta))
        try:
            seen = [r["tenant_id"] for r in await store.fetch("SELECT tenant_id FROM tenants")]
            assert seen == [ta], f"PgStore under ctx=A must see only A, got {seen}"
            # A cross-tenant write through the store API is rejected by RLS WITH CHECK.
            import asyncpg

            with pytest.raises(asyncpg.PostgresError):
                await store.execute(
                    "INSERT INTO api_keys(key_id, tenant_id, key_hash, prefix, scopes) "
                    "VALUES ($1,$2,$3,$4,'[]'::jsonb)",
                    "key_d1_" + sufix,
                    tb,
                    "h_d1",
                    "d1****",
                )
        finally:
            reset(tok)

        # After reset, back to _system → both visible again (no GUC leak).
        after = [r["tenant_id"] for r in await store.fetch("SELECT tenant_id FROM tenants")]
        assert ta in after and tb in after, f"reset must restore _system, got {after}"
    finally:
        await store.close()
        with contextlib.suppress(Exception):
            await admin.execute("DELETE FROM api_keys WHERE key_id LIKE $1", "key_d1_%")
        await _cleanup_tenants(admin, (ta, tb))
        await admin.close()


async def test_pgstore_guc_leak_check_across_pool_reuse():
    # D1 safety: a GUC set under one tenant context must NOT leak to the next
    # acquire on the same pooled connection. asyncpg resets session GUCs on
    # release, so a second request with no context returns to _system even if
    # the same physical connection is reused. Guards against cross-tenant
    # fence erosion under pool reuse.

    from fusion_core.tenant.context import TenantContext, reset, set_context

    from fusion_identity.db import PgStore

    admin = await _admin_conn()
    sufix = uuid.uuid4().hex[:8]
    ta, tb = await _seed_two_tenants(admin, sufix)
    store = PgStore(APP_ROLE_URL, pool_max=1)
    await store.connect()
    try:
        tok = set_context(TenantContext(tenant_id=ta))
        try:
            seen = [r["tenant_id"] for r in await store.fetch("SELECT tenant_id FROM tenants")]
            assert seen == [ta]
        finally:
            reset(tok)
        # Force several reuses of the single pooled connection with no context.
        for _ in range(5):
            both = [r["tenant_id"] for r in await store.fetch("SELECT tenant_id FROM tenants")]
            assert ta in both and tb in both, "GUC leaked across pool reuse"
    finally:
        await store.close()
        await _cleanup_tenants(admin, (ta, tb))
        await admin.close()
