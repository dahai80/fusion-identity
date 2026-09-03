from __future__ import annotations

import logging
import os
import uuid

import pytest

logger = logging.getLogger(__name__)

PG_URL = os.environ.get(
    "FUSION_IDENTITY_DATABASE_URL",
    "postgresql://postgres:pgpassword@127.0.0.1:5433/fusion_tenant",
)

pytestmark = pytest.mark.integration


async def _cleanup(store, tenant_id):
    import contextlib

    deletes = [
        "DELETE FROM audit_log WHERE tenant_id=$1",
        "DELETE FROM usage_ledger WHERE tenant_id=$1",
        "DELETE FROM refresh_tokens WHERE tenant_id=$1",
        "DELETE FROM revoked_jtis WHERE tenant_id=$1",
        "DELETE FROM issued_jtis WHERE tenant_id=$1",
        "DELETE FROM api_keys WHERE tenant_id=$1",
        "DELETE FROM tenant_members WHERE tenant_id=$1",
        "DELETE FROM identity_providers WHERE tenant_id=$1",
        "DELETE FROM quotas WHERE tenant_id=$1",
        "DELETE FROM tenants WHERE tenant_id=$1",
    ]
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM users WHERE user_id LIKE 'usr\\_%'")
    for sql in deletes:
        with contextlib.suppress(Exception):
            await store.execute(sql, tenant_id)


async def _two_stores():
    # D4: two independent PgStore instances (separate pools, like two workers or
    # two service replicas) against the SAME Postgres. HA consistency means state
    # written by instance A is immediately visible to instance B.
    from fusion_identity.db import PgStore

    a = PgStore(PG_URL, pool_max=4)
    b = PgStore(PG_URL, pool_max=4)
    await a.connect()
    await a.ensure_schema()
    await b.connect()
    await b.ensure_schema()
    return a, b


async def test_ha_tenant_created_on_a_visible_on_b():
    # A tenant created by instance A must be readable by instance B with no
    # cache-busting tricks — the DB is the shared source of truth. If B could
    # not see A's tenant, the service is not multi-instance safe.
    from fusion_identity.db import PgStore

    a, b = await _two_stores()
    tid = "ha_" + uuid.uuid4().hex[:8]
    try:
        await a.create_tenant(tid, "HA Tenant A", plan="standard")
        seen_b = await b.get_tenant(tid)
        assert seen_b is not None, "tenant created on A not visible on B"
        assert seen_b["tenant_id"] == tid
        assert seen_b["display_name"] == "HA Tenant A"
        logger.info("ha: tenant %s created on A visible on B", tid)
    finally:
        await a.close()
        await b.close()
        # cleanup via a fresh single store (a/b pools closed)
        c = PgStore(PG_URL)
        await c.connect()
        await _cleanup(c, tid)
        await c.close()


async def test_ha_issued_jti_on_a_is_known_on_b():
    # A jti recorded as issued by instance A must be recognized as issued by
    # instance B (replay defense spans instances). issued_jtis is the shared
    # ledger — without cross-instance visibility, a token replayed against B
    # after issuance on A would not be detectable.
    from fusion_identity.db import PgStore

    a, b = await _two_stores()
    tid = "ha_" + uuid.uuid4().hex[:8]
    uid = "usr_" + uuid.uuid4().hex[:8]
    jti = "jti_" + uuid.uuid4().hex
    try:
        await a.create_tenant(tid, "HA JTI Tenant")
        await a.create_user(uid, uid, "pw12345678")
        await a.add_member(tid, uid, "member")
        await a.record_issued_jti(jti, tid, uid)
        owner_b = await b.get_jti_owner(jti)
        assert owner_b is not None, "issued jti on A not recognized on B"
        assert owner_b[0] == tid, f"jti owner tenant mismatch: {owner_b}"
        logger.info("ha: jti %s issued on A known on B (owner=%s)", jti, owner_b)
    finally:
        await a.close()
        await b.close()
        c = PgStore(PG_URL)
        await c.connect()
        await _cleanup(c, tid)
        await c.close()


async def test_ha_revoked_jti_on_a_is_revoked_on_b():
    # A jti revoked on instance A must be treated as revoked by instance B —
    # revocation is cross-instance (logout/rotate invalidates everywhere). If B
    # accepted a jti revoked on A, a logged-out token would survive on another
    # replica, breaking the revocation contract.
    from fusion_identity.db import PgStore

    a, b = await _two_stores()
    tid = "ha_" + uuid.uuid4().hex[:8]
    uid = "usr_" + uuid.uuid4().hex[:8]
    jti = "jti_" + uuid.uuid4().hex
    try:
        await a.create_tenant(tid, "HA Revoke Tenant")
        await a.create_user(uid, uid, "pw12345678")
        await a.add_member(tid, uid, "member")
        await a.record_issued_jti(jti, tid, uid)
        await a.revoke_jti(jti, tenant_id=tid, reason="ha_test")
        revoked_b = await b.is_jti_revoked(jti)
        assert revoked_b is True, "jti revoked on A not treated as revoked on B"
        logger.info("ha: jti %s revoked on A is revoked on B", jti)
    finally:
        await a.close()
        await b.close()
        c = PgStore(PG_URL)
        await c.connect()
        await _cleanup(c, tid)
        await c.close()


async def test_ha_audit_chain_consistent_across_instances():
    # Audit records are append-only and hash-chained. A record appended on
    # instance A must be visible on B, and the chain hash must remain unbroken
    # across the two writers (B's next record chains to A's last). A broken
    # chain means tampering or lost writes — either is a HA correctness failure.
    from fusion_identity.db import PgStore

    a, b = await _two_stores()
    tid = "ha_" + uuid.uuid4().hex[:8]
    try:
        await a.create_tenant(tid, "HA Audit Tenant")
        await a.append_audit(tid, "usr_ha", None, "tenant_admin", "create", "tenant", "first on A")
        await b.append_audit(tid, "usr_ha", None, "tenant_admin", "create", "tenant", "second on B")
        records_a = await a.list_audit(tid, limit=100)
        records_b = await b.list_audit(tid, limit=100)
        assert len(records_a) >= 2, f"A sees {len(records_a)} audit records"
        assert len(records_a) == len(records_b), "A and B disagree on audit count"
        # the chain hashes must match — both see the identical, unbroken chain.
        for ra, rb in zip(records_a, records_b, strict=True):
            assert ra["chain_hash"] == rb["chain_hash"], "audit chain hash diverged"
        # structural invariant: each record's prev_hash equals the prior chain_hash
        # (genesis for the first), and every chain_hash is non-empty.
        ordered = sorted(records_b, key=lambda r: r["seq"])
        prev = "genesis"
        for rec in ordered:
            assert rec["chain_hash"], "empty chain_hash"
            assert rec["prev_hash"] == prev, (
                f"chain link broken: prev_hash={rec['prev_hash']} expected {prev}"
            )
            prev = rec["chain_hash"]
        logger.info("ha: audit chain consistent across A/B (%d records)", len(records_b))
    finally:
        await a.close()
        await b.close()
        c = PgStore(PG_URL)
        await c.connect()
        await _cleanup(c, tid)
        await c.close()


async def test_ha_usage_ledger_write_on_a_aggregates_on_b():
    # Usage recorded on instance A must count toward the aggregate a query on
    # instance B returns (quota enforcement is global, not per-replica). A token
    # spent on A that B does not see lets a tenant exceed its daily quota by
    # spreading calls across replicas.
    from fusion_identity.db import PgStore

    a, b = await _two_stores()
    tid = "ha_" + uuid.uuid4().hex[:8]
    try:
        await a.create_tenant(tid, "HA Usage Tenant")
        await a.record_usage(tid, None, metric="tokens", value=1000, source="grpc", model="m")
        await a.record_usage(tid, None, metric="tokens", value=500, source="grpc", model="m")
        agg_b = await b.aggregate_usage(tid, since=0)
        total_b = sum(int(r.get("value", 0)) for r in agg_b if r.get("metric") == "tokens")
        assert total_b == 1500, f"B saw {total_b} tokens, expected 1500 (A's writes)"
        logger.info("ha: usage 1500 tokens on A aggregates to %d on B", total_b)
    finally:
        await a.close()
        await b.close()
        c = PgStore(PG_URL)
        await c.connect()
        await _cleanup(c, tid)
        await c.close()
