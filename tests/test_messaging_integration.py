from __future__ import annotations

import logging
import os

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
    yield s
    await s.close()


async def _cleanup(store: PgStore, tenant_id: str) -> None:
    import contextlib

    await store.execute("DELETE FROM messages WHERE tenant_id=$1", tenant_id)
    await store.execute(
        "DELETE FROM conversation_reads",
    )
    await store.execute("DELETE FROM conversations WHERE tenant_id=$1", tenant_id)
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM quotas WHERE tenant_id=$1", tenant_id)
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM tenants WHERE tenant_id=$1", tenant_id)


async def test_pgstore_messaging_roundtrip(store: PgStore):
    tid = "inttest_messaging"
    await _cleanup(store, tid)
    await store.create_tenant(tid, "Messaging Tenant", plan="team")

    conv = await store.create_conversation(
        tid, "conv-int-1", "factory_order", "ORD-1", "subj", "u1"
    )
    # TIMESTAMPTZ normalized to epoch floats (issue #39/#40 class of bug).
    assert isinstance(conv["created_at"], float) and conv["created_at"] > 0
    assert isinstance(conv["updated_at"], float) and conv["updated_at"] > 0

    assert await store.get_conversation(tid, "conv-int-1") is not None
    assert await store.get_conversation("other", "conv-int-1") is None

    m1 = await store.append_message(tid, "conv-int-1", "u1", "customer", "hello")
    m2 = await store.append_message(tid, "conv-int-1", "op", "operator", "hi")
    assert m2["id"] == m1["id"] + 1
    assert isinstance(m1["id"], int)
    assert isinstance(m1["created_at"], float) and m1["created_at"] > 0

    rows = await store.list_conversations(tid, viewer_id="u1", viewer_username="u1")
    assert len(rows) == 1
    assert rows[0]["unread"] == 1  # op's message unread for u1
    rows = await store.list_conversations(
        tid, created_by="u1", viewer_id="op", viewer_username="op"
    )
    assert len(rows) == 1
    assert rows[0]["unread"] == 1  # u1's message unread for op
    rows = await store.list_conversations(
        tid, created_by="nobody", viewer_id="op", viewer_username="op"
    )
    assert rows == []

    assert len(await store.list_messages(tid, "conv-int-1")) == 2
    assert len(await store.list_messages(tid, "conv-int-1", after_id=m1["id"])) == 1

    ok = await store.set_conversation(
        tid, "conv-int-1", status="in-progress", linked_issue_id="x#1"
    )
    assert ok is True
    assert await store.set_conversation("other", "conv-int-1", status="fixed") is False
    conv = await store.get_conversation(tid, "conv-int-1")
    assert conv["status"] == "in-progress" and conv["linked_issue_id"] == "x#1"

    await store.mark_conversation_read(tid, "conv-int-1", "u1", m1["id"])
    await store.mark_conversation_read(tid, "conv-int-1", "u1", m2["id"])
    rows = await store.list_conversations(tid, viewer_id="u1", viewer_username="u1")
    assert rows[0]["unread"] == 0  # GREATEST keeps the higher marker

    await _cleanup(store, tid)
