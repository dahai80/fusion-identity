from __future__ import annotations

import contextlib
import logging
import os
import time

import pytest

from fusion_identity.db import PgStore

logger = logging.getLogger(__name__)

PG_URL = os.environ.get(
    "FUSION_IDENTITY_DATABASE_URL",
    "postgresql://postgres:pgpassword@127.0.0.1:5433/fusion_identity",
)

pytestmark = pytest.mark.integration

_PREFIX = "pgreflow99_"


@pytest.fixture
async def store():
    s = PgStore(PG_URL)
    await s.connect()
    await s.ensure_schema()
    yield s
    await s.close()


async def _cleanup(store: PgStore) -> None:
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM users WHERE user_id LIKE $1", f"{_PREFIX}%")


async def test_pg_migration_0025_column_default_true(store):
    # Migration 0025: users.data_reflow_enabled BOOLEAN NOT NULL DEFAULT TRUE.
    col = await store.fetchrow(
        "SELECT column_default, is_nullable, data_type FROM information_schema.columns "
        "WHERE table_name='users' AND column_name='data_reflow_enabled'"
    )
    assert col is not None, "migration 0025 not applied — data_reflow_enabled column missing"
    assert col["data_type"] == "boolean"
    assert col["is_nullable"] == "NO"
    assert "TRUE" in (col["column_default"] or "").upper()


async def test_pg_flag_persist_and_batch(store):
    uid = f"{_PREFIX}{os.getpid()}_{int(time.time())}"
    uid2 = f"{_PREFIX}b_{os.getpid()}_{int(time.time())}"
    await store.create_user(uid, f"user_{uid}", "S3curePass!2026x", email=f"{uid}@example.com")
    await store.create_user(uid2, f"user_{uid2}", "S3curePass!2026x", email=f"{uid2}@example.com")
    try:
        assert await store.data_reflow_enabled(uid) is True
        assert await store.set_data_reflow_enabled(uid, False) is True
        assert await store.data_reflow_enabled(uid) is False
        # Setting again is idempotent and still reports the row exists.
        assert await store.set_data_reflow_enabled(uid, False) is True
        # Batch flags: existing users reflect stored value, missing default True.
        flags = await store.data_reflow_flags([uid, uid2, "usr_missing"])
        assert flags[uid] is False
        assert flags[uid2] is True
        assert flags["usr_missing"] is True
        logger.info("pg data_reflow flag persist + batch verified uid=%s", uid)
    finally:
        await _cleanup(store)


async def test_pg_unknown_user_flag_defaults_true(store):
    assert await store.data_reflow_enabled("pgreflow99_no_such_user") is True
    assert await store.set_data_reflow_enabled("pgreflow99_no_such_user", False) is False
