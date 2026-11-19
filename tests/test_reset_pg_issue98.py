from __future__ import annotations

import contextlib
import hashlib
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


@pytest.fixture
async def store():
    s = PgStore(PG_URL)
    await s.connect()
    await s.ensure_schema()
    yield s
    await s.close()


async def _cleanup(store: PgStore, prefix: str) -> None:
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM users WHERE user_id LIKE $1", f"{prefix}%")


async def test_pg_clear_password_reset_token(store):
    # Issue #98: change_password invalidates an armed reset token on PG —
    # the clear must NULL both columns (InMemory/PG contract parity).
    uid = f"pgreset98_{os.getpid()}_{int(time.time())}"
    await store.create_user(uid, f"user_{uid}", "S3curePass!2026x", email=f"{uid}@example.com")
    try:
        token = "pg-tok-abcdef123456"
        ok = await store.set_password_reset_token(
            uid, hashlib.sha256(token.encode()).hexdigest(), time.time() + 1800
        )
        assert ok
        cleared = await store.clear_password_reset_token(uid)
        assert cleared is True
        consumed = await store.consume_password_reset_token(
            hashlib.sha256(token.encode()).hexdigest()
        )
        assert consumed is None, "token must be dead after password change"
        # Clearing again is idempotent and still reports the row exists.
        assert await store.clear_password_reset_token(uid) is True
        # Unknown user → False, never an exception.
        assert await store.clear_password_reset_token("pgreset98_no_such_user") is False
        logger.info("pg clear_password_reset_token verified user=%s", uid)
    finally:
        await _cleanup(store, "pgreset98_")
