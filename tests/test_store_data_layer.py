from __future__ import annotations

import asyncio
import time

from fusion_identity.store import InMemoryStore


async def test_append_audit_per_tenant_chain_multitenant():
    # T10/F12: multi-tenant InMemory audit chain must verify valid when records
    # interleave across tenants. prev_hash is per-tenant, not global.
    store = InMemoryStore()
    await store.create_tenant("a", "A")
    await store.create_tenant("b", "B")
    await store.append_audit("a", None, None, None, "act1", "r", {"x": 1})
    await store.append_audit("b", None, None, None, "act2", "r", {"y": 2})
    await store.append_audit("a", None, None, None, "act3", "r", {"z": 3})
    res_a = await store.verify_audit_chain("a")
    assert res_a["valid"] is True, res_a
    res_b = await store.verify_audit_chain("b")
    assert res_b["valid"] is True, res_b


async def test_append_audit_chain_order_desc():
    # F19: list_audit returns newest-first (DESC by id).
    store = InMemoryStore()
    await store.create_tenant("a", "A")
    await store.append_audit("a", None, None, None, "first", "r", {})
    await store.append_audit("a", None, None, None, "second", "r", {})
    rows = await store.list_audit("a", limit=100)
    assert [r["action"] for r in rows] == ["second", "first"]


async def test_append_audit_concurrent_no_fork():
    # T10/F12: concurrent appends to the same tenant must not fork the hash chain.
    # InMemory is single-threaded (asyncio), so concurrency here is interleaved
    # tasks — the chain must still verify valid.
    store = InMemoryStore()
    await store.create_tenant("a", "A")

    async def append(i: int):
        await store.append_audit("a", None, None, None, f"act{i}", "r", {"i": i})

    await asyncio.gather(*(append(i) for i in range(20)))
    res = await store.verify_audit_chain("a")
    assert res["valid"] is True, res


async def test_list_audit_cursor_desc():
    # F19: cursor excludes id >= cursor (DESC paging), returns newest window.
    store = InMemoryStore()
    await store.create_tenant("a", "A")
    ids = []
    for i in range(5):
        rec = await store.append_audit("a", None, None, None, f"act{i}", "r", {"i": i})
        ids.append(rec["id"])
    # first page: newest 2
    page1 = await store.list_audit("a", limit=2)
    assert [r["id"] for r in page1] == [ids[4], ids[3]]
    # next page: older than ids[3]
    page2 = await store.list_audit("a", limit=2, cursor=ids[3])
    assert [r["id"] for r in page2] == [ids[2], ids[1]]


async def test_delete_mfa_inmemory_true():
    # F19: InMemory delete_mfa returns True on delete (parity with PgStore RETURNING fix).
    store = InMemoryStore()
    await store.create_user("u1", "u1", "pw12345678")
    await store.upsert_mfa("u1", "totp", secret_enc="enc", enabled=True)
    assert await store.delete_mfa("u1", "totp") is True
    assert await store.delete_mfa("u1", "totp") is False


async def test_revoked_jti_sweep_expired():
    # P7: is_jti_revoked sweeps expired entries; an expired jti is no longer revoked.
    store = InMemoryStore()
    jti = "jti-expired"
    store._revoked_jtis[jti] = {
        "jti": jti,
        "tenant_id": "a",
        "expires_at": time.time() - 1,
    }
    assert await store.is_jti_revoked(jti) is False
    assert jti not in store._revoked_jtis


async def test_revoked_jti_sweep_keeps_active():
    # P7: a not-yet-expired jti stays revoked after sweep.
    store = InMemoryStore()
    jti = "jti-active"
    store._revoked_jtis[jti] = {
        "jti": jti,
        "tenant_id": "a",
        "expires_at": time.time() + 3600,
    }
    assert await store.is_jti_revoked(jti) is True
