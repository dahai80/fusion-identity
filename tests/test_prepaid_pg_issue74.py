from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest

from tests.test_acceptance_issue71 import PG_URL

logger = __import__("logging").getLogger(__name__)

_TENANT = "pgprepaid74"


@pytest.fixture
async def prepaid_pg():
    import redis.asyncio as aioredis

    from fusion_identity.cache import IdentityCache
    from fusion_identity.concurrency import ConcurrencyManager
    from fusion_identity.db import PgStore
    from fusion_identity.grpc_server import serve as serve_grpc
    from fusion_identity.store import sha256_hash
    from tests.conftest import _settings
    from tests.test_acceptance_issue71 import _REDIS_URL, _TEST_GRPC_PORT

    store = PgStore(PG_URL)
    await store.connect()
    await store.ensure_schema()
    cleanup = [
        "DELETE FROM balance_ledger WHERE tenant_id=$1",
        "DELETE FROM prepaid_orders WHERE tenant_id=$1",
        "DELETE FROM event_outbox WHERE tenant_id=$1",
        "DELETE FROM usage_ledger WHERE tenant_id=$1",
        "DELETE FROM lease_log WHERE tenant_id=$1",
        "DELETE FROM api_keys WHERE tenant_id=$1",
        "DELETE FROM quotas WHERE tenant_id=$1",
        "DELETE FROM tenant_members WHERE tenant_id=$1",
        "DELETE FROM tenants WHERE tenant_id=$1",
    ]
    for sql in cleanup:
        with contextlib.suppress(Exception):
            await store.execute(sql, _TENANT)

    await store.create_tenant(_TENANT, "Issue 74 Prepaid")
    raw_key, _row = await store.create_api_key(_TENANT, None, ["inference"])
    await store.put_quota(_TENANT, concurrent=2, tpm=1000, allowed_modules=[])

    rclient = aioredis.from_url(_REDIS_URL, decode_responses=True)
    keys = [k async for k in rclient.scan_iter(f"quota:{_TENANT}:*")]
    keys += [k async for k in rclient.scan_iter(f"leases:{_TENANT}")]
    keys += [k async for k in rclient.scan_iter(f"rpm:{_TENANT}")]
    keys.append(f"apikey:{sha256_hash(raw_key)}")
    if keys:
        await rclient.delete(*keys)

    cache = IdentityCache(rclient)
    concurrency = ConcurrencyManager(rclient, lease_ttl=60)
    await cache.init_scripts()
    await concurrency.init_scripts()

    s = _settings()
    fake_app = SimpleNamespace(
        state=SimpleNamespace(settings=s, store=store, cache=cache, concurrency=concurrency)
    )
    server = await serve_grpc(fake_app, host="127.0.0.1", port=_TEST_GRPC_PORT)
    ns = SimpleNamespace(
        store=store,
        redis=rclient,
        raw_key=raw_key,
        service_token=s.service_token,
    )
    yield ns
    await server.stop(0)
    keys = [k async for k in rclient.scan_iter(f"quota:{_TENANT}:*")]
    keys += [k async for k in rclient.scan_iter(f"leases:{_TENANT}")]
    keys += [k async for k in rclient.scan_iter(f"rpm:{_TENANT}")]
    keys.append(f"apikey:{sha256_hash(raw_key)}")
    if keys:
        await rclient.delete(*keys)
    await rclient.aclose()
    for sql in cleanup:
        with contextlib.suppress(Exception):
            await store.execute(sql, _TENANT)
    await store.close()


@pytest.mark.integration
async def test_pg_prepaid_order_pay_balance(prepaid_pg):
    store = prepaid_pg.store
    order = await store.create_prepaid_order(_TENANT, 1000, 200, "stub")
    assert order["status"] == "created"
    assert await store.get_balance(_TENANT) == 0
    paid = await store.mark_prepaid_order_paid(order["order_id"], "ref_pg_1")
    assert paid["status"] == "paid"
    assert await store.get_balance(_TENANT) == 1200
    # Idempotent replay under PG: no double credit.
    replay = await store.mark_prepaid_order_paid(order["order_id"], "ref_pg_2")
    assert replay["provider_ref"] == "ref_pg_1"
    assert await store.get_balance(_TENANT) == 1200
    balance = await store.debit_balance(_TENANT, 300, "lease_pg")
    assert balance == 900
    assert await store.count_paid_prepaid_orders(_TENANT) == 1
    orders = await store.list_prepaid_orders(_TENANT)
    assert len(orders) == 1


@pytest.mark.integration
async def test_pg_grpc_exhaust_then_recharge_same_key(prepaid_pg):
    from fusion_identity.client.identity_client import IdentityClient
    from fusion_identity.grpc import identity_pb2 as pb
    from tests.test_acceptance_issue71 import _TEST_GRPC_PORT

    store = prepaid_pg.store
    ic = IdentityClient(
        target=f"127.0.0.1:{_TEST_GRPC_PORT}",
        deadline_ms=2000,
        service_token=prepaid_pg.service_token,
    )
    try:
        # Burn the free daily quota (tpm=1000).
        resp = await ic.authorize_and_acquire(prepaid_pg.raw_key, "office")
        assert resp.is_allowed, resp.error_message
        usage = await ic.report_usage(
            resp.lease_id, _TENANT, "m", prompt_tokens=1000, completion_tokens=0
        )
        assert usage is not None
        # Quota gone, balance 0 -> BALANCE_EXHAUSTED on the same key.
        resp2 = await ic.authorize_and_acquire(prepaid_pg.raw_key, "office")
        assert not resp2.is_allowed
        assert resp2.error_code == pb.AuthErrorCode.BALANCE_EXHAUSTED
        assert resp2.error_message

        # Recharge over HTTP-plane store calls: same key unblocks immediately.
        order = await store.create_prepaid_order(_TENANT, 5000, 0, "stub")
        await store.mark_prepaid_order_paid(order["order_id"], "ref_unblock")
        resp3 = await ic.authorize_and_acquire(prepaid_pg.raw_key, "office")
        assert resp3.is_allowed, resp3.error_message
        await ic.release_lease(resp3.lease_id, _TENANT)
    finally:
        await ic.close()


@pytest.mark.integration
async def test_pg_promo_granted_once(prepaid_pg):
    store = prepaid_pg.store
    assert await store.count_paid_prepaid_orders(_TENANT) == 0
    first = await store.create_prepaid_order(_TENANT, 1000, 200, "stub")
    await store.mark_prepaid_order_paid(first["order_id"], "ref_a")
    assert await store.count_paid_prepaid_orders(_TENANT) == 1
    second = await store.create_prepaid_order(_TENANT, 1000, 0, "stub")
    await store.mark_prepaid_order_paid(second["order_id"], "ref_b")
    assert await store.count_paid_prepaid_orders(_TENANT) == 2
    # Ledger: 1200 (first incl. promo) + 1000 (second) - debits = balance.
    assert await store.get_balance(_TENANT) == 2200
