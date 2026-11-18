from __future__ import annotations

import logging
import os
import time

import asyncpg
import pytest

from fusion_identity.migrations import (
    assert_app_role_privileges,
    grant_app_role,
    run_migrations,
)

logger = logging.getLogger(__name__)

PG_ADMIN_URL = os.environ.get(
    "FUSION_IDENTITY_PG_ADMIN_URL",
    "postgresql://postgres:pgpassword@127.0.0.1:5433/postgres",
)
APP_ROLE = "fusion_identity_app"

pytestmark = pytest.mark.integration


async def _app_role_exists(conn) -> bool:
    return await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname=$1", APP_ROLE) is not None


@pytest.fixture
async def scratch_db():
    admin = await asyncpg.connect(PG_ADMIN_URL)
    name = f"fi94_{int(time.time())}_{os.getpid()}"
    await admin.execute(f'CREATE DATABASE "{name}"')
    # The app role must exist for the grant/probe plane; tests create it
    # server-wide once if the operator has not (matching prod).
    if not await _app_role_exists(admin):
        await admin.execute(f"CREATE ROLE {APP_ROLE} LOGIN")
    yield name, admin
    await admin.execute(f'DROP DATABASE IF EXISTS "{name}"')
    await admin.close()


async def test_fresh_migration_run_grants_app_role(scratch_db):
    # Issue #94 acceptance: fresh database + full migration run -> every
    # table readable by the app role, NO manual GRANTs.
    name, admin = scratch_db
    pool = await asyncpg.create_pool(PG_ADMIN_URL.rsplit("/", 1)[0] + f"/{name}")
    try:
        done = await run_migrations(pool)
        assert len(done) >= 24, "expected the full migration chain on a fresh DB"
        async with pool.acquire() as conn:
            tables = await conn.fetch(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema='public' AND table_type='BASE TABLE' "
                "AND table_name <> 'schema_migrations'"
            )
            assert tables, "migrations created no tables"
            for r in tables:
                ok = await conn.fetchval(
                    "SELECT has_table_privilege($1, $2, 'SELECT')", APP_ROLE, r["table_name"]
                )
                assert ok, f"app role cannot SELECT {r['table_name']} after fresh run"
            # Probe itself must pass (no exception).
            await assert_app_role_privileges(conn)
        logger.info("fresh-run grant plane verified: %d tables", len(tables))
    finally:
        await pool.close()


async def test_probe_fails_loudly_on_missing_grant(scratch_db):
    # Issue #94: a table the app role cannot read must abort startup with a
    # loud RuntimeError listing the table (not a silent pass).
    name, admin = scratch_db
    pool = await asyncpg.create_pool(PG_ADMIN_URL.rsplit("/", 1)[0] + f"/{name}")
    try:
        await run_migrations(pool)
        async with pool.acquire() as conn:
            await conn.execute(f"REVOKE SELECT ON public.users FROM {APP_ROLE}")
            with pytest.raises(RuntimeError) as ei:
                await assert_app_role_privileges(conn)
        assert "users" in str(ei.value)
        logger.info("loud-fail probe verified")
    finally:
        await pool.close()


async def test_grant_app_role_missing_role_noop(scratch_db, monkeypatch):
    # Unknown role is a warning + False, never an exception.
    name, admin = scratch_db
    monkeypatch.setenv("FUSION_IDENTITY_APP_ROLE", "fi94_no_such_role")
    pool = await asyncpg.create_pool(PG_ADMIN_URL.rsplit("/", 1)[0] + f"/{name}")
    try:
        async with pool.acquire() as conn:
            assert await grant_app_role(conn) is False
    finally:
        await pool.close()
