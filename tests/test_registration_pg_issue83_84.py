from __future__ import annotations

import contextlib

import pytest

from fusion_identity.store import StoreConflict
from tests.test_acceptance_issue71 import PG_URL

_UNAMES = ["pg83dup", "pg83other"]


@pytest.fixture
async def reg_pg():
    from fusion_identity.db import PgStore

    store = PgStore(PG_URL)
    await store.connect()
    # ensure_schema applies migrations, including 0023 (users_username_uniq).
    await store.ensure_schema()
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM issued_jtis WHERE tenant_id='community'")
    with contextlib.suppress(Exception):
        await store.execute(
            "DELETE FROM tenant_members WHERE user_id IN "
            "(SELECT user_id FROM users WHERE username = ANY($1))",
            _UNAMES,
        )
    with contextlib.suppress(Exception):
        await store.execute(
            "DELETE FROM audit_log WHERE user_id IN "
            "(SELECT user_id FROM users WHERE username = ANY($1))"
        )
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM users WHERE username = ANY($1)", _UNAMES)
    yield store
    with contextlib.suppress(Exception):
        await store.execute(
            "DELETE FROM tenant_members WHERE user_id IN "
            "(SELECT user_id FROM users WHERE username = ANY($1))",
            _UNAMES,
        )
    with contextlib.suppress(Exception):
        await store.execute(
            "DELETE FROM audit_log WHERE user_id IN "
            "(SELECT user_id FROM users WHERE username = ANY($1))"
        )
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM users WHERE username = ANY($1)", _UNAMES)
    await store.close()


@pytest.mark.integration
async def test_pg_username_unique_index(reg_pg):
    store = reg_pg
    await store.create_user("u83pg1", "pg83dup", "pass-83-83", "pg83a@x.io")
    # Same user_id: pre-existing PK conflict path (asyncpg uniqueness is
    # surfaced as StoreConflict by PgStore.create_user).
    with pytest.raises(StoreConflict):
        await store.create_user("u83pg1", "pg83dup", "pass-83-83", "pg83c@x.io")
    # Different user_id, SAME username: the issue #83 unique index must turn
    # the race into a StoreConflict (register route maps it to 409).
    with pytest.raises(StoreConflict):
        await store.create_user("u83pg2", "pg83dup", "pass-83-83", "pg83b@x.io")
    # Distinct usernames coexist.
    await store.create_user("u83pg3", "pg83other", "pass-83-83", "pg83d@x.io")
    assert await store.get_user_by_username("pg83dup") is not None
    assert await store.get_user_by_username("pg83other") is not None
