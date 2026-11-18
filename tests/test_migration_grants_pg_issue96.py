from __future__ import annotations

import logging
import os
import time

import asyncpg
import pytest

from fusion_identity.migrations import assert_app_role_privileges, run_migrations

logger = logging.getLogger(__name__)

PG_ADMIN_URL = os.environ.get(
    "FUSION_IDENTITY_PG_ADMIN_URL",
    "postgresql://postgres:pgpassword@127.0.0.1:5433/postgres",
)
APP_ROLE = "fusion_identity_app"

pytestmark = pytest.mark.integration


@pytest.fixture
async def scratch_db():
    admin = await asyncpg.connect(PG_ADMIN_URL)
    name = f"fi96_{int(time.time())}_{os.getpid()}"
    await admin.execute(f'CREATE DATABASE "{name}"')
    if not await admin.fetchval("SELECT 1 FROM pg_roles WHERE rolname=$1", APP_ROLE):
        await admin.execute(f"CREATE ROLE {APP_ROLE} LOGIN")
    yield name, admin
    await admin.execute(f'DROP DATABASE IF EXISTS "{name}"')
    await admin.close()


@pytest.mark.parametrize("priv", ["INSERT", "UPDATE", "DELETE"])
async def test_probe_catches_non_select_grant_gap(scratch_db, priv):
    # Issue #96: SELECT-only probing missed write-plane gaps — login INSERTs
    # into issued_jtis/audit_log, so a table readable but not writable would
    # still 500 the login plane. The probe must fail on ANY missing privilege.
    name, admin = scratch_db
    pool = await asyncpg.create_pool(PG_ADMIN_URL.rsplit("/", 1)[0] + f"/{name}")
    try:
        await run_migrations(pool)
        async with pool.acquire() as conn:
            await conn.execute(f"REVOKE {priv} ON public.users FROM {APP_ROLE}")
            with pytest.raises(RuntimeError) as ei:
                await assert_app_role_privileges(conn)
        assert f"users:{priv}" in str(ei.value)
        logger.info("issue #96 probe gap verified for %s", priv)
    finally:
        await pool.close()


async def test_probe_passes_full_privilege_set_after_fresh_run(scratch_db):
    # Fresh DB + full migration run + grant -> probe passes with the
    # tightened 4-privilege check, no manual GRANTs (issue #96 acceptance).
    name, admin = scratch_db
    pool = await asyncpg.create_pool(PG_ADMIN_URL.rsplit("/", 1)[0] + f"/{name}")
    try:
        done = await run_migrations(pool)
        assert len(done) >= 24
        async with pool.acquire() as conn:
            await assert_app_role_privileges(conn)
        logger.info("issue #96 full-privilege fresh-run probe passed")
    finally:
        await pool.close()
