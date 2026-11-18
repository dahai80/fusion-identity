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


@pytest.fixture
async def store():
    s = PgStore(PG_URL)
    await s.connect()
    await s.ensure_schema()
    yield s
    await s.close()


async def _cleanup(store: PgStore, prefix: str) -> None:
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM account_deletions WHERE user_id LIKE $1", f"{prefix}%")
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM users WHERE user_id LIKE $1", f"{prefix}%")


async def _seed_user(store: PgStore, prefix: str) -> str:
    uid = f"{prefix}_{os.getpid()}_{int(time.time())}"
    await store.create_user(uid, f"user_{uid}", "S3curePass!2026x", email=f"{uid}@example.com")
    return uid


async def test_pg_account_deletion_roundtrip(store):
    # Issue #91: request → pending → cancel → re-request on real PG.
    uid = await _seed_user(store, "pgacct")
    try:
        row = await store.request_account_deletion(uid, time.time() + 3600)
        assert row["status"] == "pending"
        pending = await store.pending_account_deletion(uid)
        assert pending is not None and pending["purge_at"] > time.time()
        assert await store.cancel_account_deletion(uid) is True
        assert await store.pending_account_deletion(uid) is None
        assert await store.cancel_account_deletion(uid) is False
        # Idempotent re-request keeps the FIRST deadline.
        r1 = await store.request_account_deletion(uid, time.time() + 7200)
        r2 = await store.request_account_deletion(uid, time.time() + 99999)
        assert r2["purge_at"] == r1["purge_at"]
    finally:
        await _cleanup(store, "pgacct_")


async def test_pg_purge_account_transaction(store):
    # Issue #91: the purge must clear every users-referencing table in one
    # transaction: members, api_keys, invites.created_by, jtis, mfa, audit
    # tombstoned (user_id NULL, chain intact), deletions row gone.
    uid = await _seed_user(store, "pgpurge")
    tid = f"pgpurge_tenant_{os.getpid()}"
    try:
        await store.create_tenant(tid, "Purge Tenant", plan="free")
        await store.add_member(tid, uid, role="member", added_by=None)
        await store.create_api_key(tid, uid, ["*"])
        await store.set_email_verify_token(uid, "tok", time.time() + 600)
        await store.append_audit(
            tenant_id=tid,
            user_id=uid,
            jti="jti-purge",
            role="member",
            action="test.purge_marker",
            resource=None,
            detail={"user_id": uid},
        )
        await store.request_account_deletion(uid, time.time() - 1)

        due = await store.due_account_deletions(time.time())
        assert uid in due
        await store.purge_account(uid)

        assert await store.get_user(uid) is None
        assert await store.pending_account_deletion(uid) is None
        members = await store.fetch("SELECT 1 FROM tenant_members WHERE user_id=$1", uid)
        assert members == []
        keys = await store.fetch("SELECT user_id FROM api_keys WHERE user_id=$1", uid)
        assert all(k["user_id"] is None for k in keys)
        jtis = await store.fetch("SELECT 1 FROM issued_jtis WHERE user_id=$1", uid)
        assert jtis == []
        # Audit tombstoned but not deleted (hash chain stays continuous).
        rows = await store.fetch(
            "SELECT user_id, action FROM audit_log WHERE detail->>'user_id'=$1 "
            "AND action='test.purge_marker'",
            uid,
        )
        assert len(rows) == 1 and rows[0]["user_id"] is None
        # audit_for_user returns nothing post-purge (rows no longer match).
        assert await store.audit_for_user(uid) == []
        logger.info("pg purge transaction verified user=%s", uid)
    finally:
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM audit_log WHERE tenant_id=$1", tid)
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM api_keys WHERE tenant_id=$1", tid)
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM tenant_members WHERE tenant_id=$1", tid)
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM quotas WHERE tenant_id=$1", tid)
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM tenants WHERE tenant_id=$1", tid)
        await _cleanup(store, "pgpurge_")


async def test_pg_audit_for_user_and_prune(store):
    uid = await _seed_user(store, "pgexp")
    tid = f"pgexp_tenant_{os.getpid()}"
    try:
        await store.create_tenant(tid, "Export Tenant", plan="free")
        await store.add_member(tid, uid, role="member", added_by=None)
        await store.append_audit(
            tenant_id=tid,
            user_id=uid,
            jti=None,
            role="member",
            action="test.export_marker",
            resource=None,
            detail={"k": "v"},
        )
        rows = await store.audit_for_user(uid, limit=10)
        assert any(r["action"] == "test.export_marker" for r in rows)
        # Prune with a future cutoff wipes everything; past cutoff wipes nothing.
        pruned = await store.prune_audit(time.time() + 10_000_000)
        assert pruned >= 1
        pruned2 = await store.prune_audit(time.time() - 10_000_000)
        assert pruned2 == 0
    finally:
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM audit_log WHERE tenant_id=$1", tid)
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM tenant_members WHERE tenant_id=$1", tid)
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM quotas WHERE tenant_id=$1", tid)
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM tenants WHERE tenant_id=$1", tid)
        await _cleanup(store, "pgexp_")
