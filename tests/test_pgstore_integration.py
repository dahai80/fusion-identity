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
    seqs = [r["seq"] for r in rows]
    assert seqs == sorted(seqs)
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
