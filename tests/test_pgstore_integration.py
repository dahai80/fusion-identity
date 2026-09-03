from __future__ import annotations

import logging
import os

import pytest

from fusion_identity.db import PgStore

logger = logging.getLogger(__name__)

PG_URL = os.environ.get(
    "FUSION_IDENTITY_DATABASE_URL", "postgresql://postgres:pgpassword@127.0.0.1:5433/fusion_tenant"
)

pytestmark = pytest.mark.integration


@pytest.fixture
async def store():
    s = PgStore(PG_URL)
    await s.connect()
    await s.ensure_schema()
    yield s
    await s.close()


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
    for sql in deletes:
        with contextlib.suppress(Exception):
            await store.execute(sql, tenant_id)
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM users WHERE user_id LIKE $1", f"{tenant_id}_%")


async def test_pgstore_tenant_quota_lifecycle(store):
    tid = "inttest_tenant_quota"
    await _cleanup(store, tid)
    created = await store.create_tenant(tid, "Integration Tenant", plan="team")
    assert created["tenant_id"] == tid
    fetched = await store.get_tenant(tid)
    assert fetched is not None and fetched["display_name"] == "Integration Tenant"
    quota = await store.get_quota(tid)
    assert quota is not None and quota["tenant_id"] == tid
    updated = await store.put_quota(tid, concurrent=8, tpm=500000)
    assert updated["concurrent"] == 8 and updated["tpm"] == 500000
    deleted = await store.delete_tenant(tid)
    assert deleted is True
    assert (await store.get_tenant_status(tid)) == "deleted"
    await _cleanup(store, tid)


async def test_pgstore_user_member_apikey(store):
    tid = "inttest_member"
    uid = "inttest_member_usr1"
    await _cleanup(store, tid)
    await store.create_tenant(tid, "Member Tenant")
    user = await store.create_user(
        uid,
        username="intmember@example.com",
        password="x",
    )
    assert user["user_id"] == uid
    member = await store.add_member(tid, uid, "member")
    assert member["role"] == "member"
    assert (await store.get_member_role(tid, uid)) == "member"
    raw, key_row = await store.create_api_key(tid, uid, ["models:inference"])
    assert raw.startswith("fmu_")
    assert key_row["tenant_id"] == tid
    keys = await store.list_api_keys(tid)
    assert any(k["key_id"] == key_row["key_id"] for k in keys)
    assert await store.revoke_api_key(key_row["key_id"]) is True
    assert await store.remove_member(tid, uid) is True
    await _cleanup(store, tid)


async def test_pgstore_audit_chain(store):
    tid = "inttest_audit"
    await _cleanup(store, tid)
    await store.create_tenant(tid, "Audit Tenant")
    a1 = await store.append_audit(tid, None, None, None, "tenant.create", "tenant", {"v": 1})
    a2 = await store.append_audit(tid, None, None, None, "tenant.update", "tenant", {"v": 2})
    assert a1["chain_hash"] != a2["chain_hash"]
    rows = await store.list_audit(tid, limit=10)
    assert len(rows) >= 2
    # list_audit is newest-first (DESC by id) on both backends; the second
    # append must come back before the first.
    seqs = [r["seq"] for r in rows]
    assert seqs == sorted(seqs, reverse=True)
    await _cleanup(store, tid)


async def test_pgstore_usage_upsert(store):
    tid = "inttest_usage"
    await _cleanup(store, tid)
    await store.create_tenant(tid, "Usage Tenant")
    await store.record_usage(tid, None, "prompt_tokens", 100, "grpc", "test-model")
    await store.record_usage(tid, None, "prompt_tokens", 50, "grpc", "test-model")
    rows = await store.aggregate_usage(tid, metric="prompt_tokens")
    total = sum(r["value"] for r in rows if r["metric"] == "prompt_tokens")
    assert total == 150
    await _cleanup(store, tid)


async def test_pgstore_idp_update(store):
    tid = "inttest_idp"
    idp_id = "inttest_idp_keycloak"
    await _cleanup(store, tid)
    await store.create_tenant(tid, "IdP Tenant")
    rec = await store.create_idp(
        idp_id,
        tid,
        type="oidc",
        issuer_url="http://idp.example/orig",
        client_id="c1",
        client_secret_enc="enc1",
        scopes="openid profile",
        auto_provision=True,
    )
    assert rec["issuer_url"] == "http://idp.example/orig"
    updated = await store.update_idp(
        idp_id,
        issuer_url="http://idp.example/new",
        auto_provision=False,
        client_secret_enc="enc2",
    )
    assert updated is not None
    assert updated["issuer_url"] == "http://idp.example/new"
    assert updated["auto_provision"] is False
    assert updated["client_secret_enc"] == "enc2"
    got = await store.get_idp(idp_id)
    assert got["issuer_url"] == "http://idp.example/new"
    assert await store.delete_idp(idp_id) is True
    await _cleanup(store, tid)


async def test_connect_warns_on_superuser(monkeypatch, caplog):
    # C3: a superuser connection bypasses RLS. By default connect() must warn
    # loudly (not fail) so an operator notices. The default test DSN is the
    # operator's superuser account, so this exercises the warning path.
    import logging

    s = PgStore(PG_URL)
    with caplog.at_level(logging.WARNING, logger="fusion_identity.db"):
        await s.connect()
    try:
        assert any("RLS is BYPASSED" in r.message for r in caplog.records), (
            "superuser connect must warn RLS bypassed"
        )
    finally:
        await s.close()


async def test_connect_fails_closed_when_rls_required(monkeypatch):
    # C3: with FUSION_IDENTITY_REQUIRE_RLS=1 a superuser connection must
    # fail-closed (StoreError) rather than silently deploy without RLS.
    monkeypatch.setenv("FUSION_IDENTITY_REQUIRE_RLS", "1")
    s = PgStore(PG_URL)
    with pytest.raises(Exception, match="REQUIRE_RLS"):
        await s.connect()
    # connect() closes the pool on failure; ensure no leak.
    assert s._pool is None


async def test_stateful_artifacts_survive_restart():
    # C4: HA claim — stateful artifacts (refresh_token, revoked_jti) must
    # persist in Postgres across a process restart (close + reconnect pool).
    # Verifies multi-instance/restart consistency for the auth-critical state
    # that lives in the DB, not in memory.
    import time

    s1 = PgStore(PG_URL)
    await s1.connect()
    await s1.ensure_schema()
    tid = "inttest_restart"
    uid = "inttest_restart_user"
    await _cleanup(s1, tid)
    with __import__("contextlib").suppress(Exception):
        await s1.execute("DELETE FROM users WHERE user_id=$1", uid)
    await s1.create_tenant(tid, "Restart Tenant")
    await s1.create_user(uid, "restartuser", "pw123456")
    await s1.add_member(tid, uid, "member")
    jti_rt = "rt_restart_" + __import__("uuid").uuid4().hex[:8]
    await s1.insert_refresh_token(
        jti_rt, "fam_restart", tid, uid, time.time() + 3600, status="active"
    )
    jti_rev = "rev_restart_" + __import__("uuid").uuid4().hex[:8]
    await s1.revoke_jti(jti_rev, tenant_id=tid, user_id=uid, expires_at=time.time() + 3600)
    # Simulate restart: close pool, open a fresh PgStore.
    await s1.close()

    s2 = PgStore(PG_URL)
    await s2.connect()
    try:
        rt = await s2.get_refresh_token(jti_rt)
        assert rt is not None and rt["status"] == "active", "refresh_token lost on restart"
        assert rt["tenant_id"] == tid and rt["user_id"] == uid
        assert await s2.is_jti_revoked(jti_rev) is True, "revoked_jti lost on restart"
    finally:
        await _cleanup(s2, tid)
        with __import__("contextlib").suppress(Exception):
            await s2.execute("DELETE FROM users WHERE user_id=$1", uid)
        await s2.close()


async def _cleanup_all_residue():
    # Safety net: clear any inttest_* residue left by prior runs so the suite
    # is hermetic regardless of insertion order.
    import contextlib

    s = PgStore(PG_URL)
    await s.connect()
    try:
        for sql in (
            "DELETE FROM refresh_tokens WHERE tenant_id LIKE 'inttest_%'",
            "DELETE FROM revoked_jtis WHERE tenant_id LIKE 'inttest_%'",
            "DELETE FROM issued_jtis WHERE tenant_id LIKE 'inttest_%'",
            "DELETE FROM audit_log WHERE tenant_id LIKE 'inttest_%'",
            "DELETE FROM api_keys WHERE tenant_id LIKE 'inttest_%'",
            "DELETE FROM tenant_members WHERE tenant_id LIKE 'inttest_%'",
            "DELETE FROM quotas WHERE tenant_id LIKE 'inttest_%'",
            "DELETE FROM tenants WHERE tenant_id LIKE 'inttest_%'",
            "DELETE FROM users WHERE user_id LIKE 'inttest_%'",
        ):
            with contextlib.suppress(Exception):
                await s.execute(sql)
    finally:
        await s.close()
