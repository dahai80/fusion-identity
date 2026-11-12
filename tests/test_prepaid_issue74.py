from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import fakeredis.aioredis
import grpc
import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.cache import IdentityCache
from fusion_identity.concurrency import ConcurrencyManager
from fusion_identity.grpc import identity_pb2 as pb
from fusion_identity.grpc import identity_pb2_grpc as pb_grpc
from fusion_identity.grpc_servicer import IdentityServiceServicer
from fusion_identity.payments import PaymentError, compute_promo, get_provider
from fusion_identity.store import InMemoryStore
from tests.conftest import TEST_SERVICE_TOKEN, _settings

AUTH = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


def _client(store: InMemoryStore, **overrides):
    s = dataclasses.replace(_settings(), **overrides)
    app = build_app(s, store=store, run_bootstrap=False)
    return TestClient(app), s


# ---------------------------------------------------------------------------
# Store layer: order lifecycle, idempotent pay, ledger-derived balance
# ---------------------------------------------------------------------------


async def test_order_lifecycle_and_balance():
    store = InMemoryStore()
    await store.connect()
    try:
        await store.create_tenant("t1", display_name="T1")
        order = await store.create_prepaid_order("t1", 1000, 0, "stub")
        assert order["status"] == "created"
        assert await store.get_balance("t1") == 0

        paid = await store.mark_prepaid_order_paid(order["order_id"], "ref_1")
        assert paid["status"] == "paid"
        assert paid["provider_ref"] == "ref_1"
        assert await store.get_balance("t1") == 1000

        # Idempotent replay: second pay call must not double-credit.
        replay = await store.mark_prepaid_order_paid(order["order_id"], "ref_2")
        assert replay["status"] == "paid"
        assert replay["provider_ref"] == "ref_1"
        assert await store.get_balance("t1") == 1000

        balance = await store.debit_balance("t1", 400, "lease_x")
        assert balance == 600
        orders = await store.list_prepaid_orders("t1")
        assert len(orders) == 1 and orders[0]["order_id"] == order["order_id"]
    finally:
        await store.close()


async def test_mark_paid_unknown_and_cancelled_refuse():
    store = InMemoryStore()
    await store.connect()
    try:
        assert await store.mark_prepaid_order_paid("pre_nope", None) is None
        await store.create_tenant("t1", display_name="T1")
        order = await store.create_prepaid_order("t1", 100, 0, "stub")
        # Simulate a cancelled order: only 'created' may transition to paid.
        store._prepaid_orders[order["order_id"]]["status"] = "cancelled"
        assert await store.mark_prepaid_order_paid(order["order_id"], None) is None
        assert await store.get_balance("t1") == 0
    finally:
        await store.close()


async def test_debit_zero_tokens_is_noop():
    store = InMemoryStore()
    await store.connect()
    try:
        await store.create_tenant("t1", display_name="T1")
        await store.create_prepaid_order("t1", 500, 0, "stub")
        await store.mark_prepaid_order_paid(
            (await store.list_prepaid_orders("t1"))[0]["order_id"], None
        )
        balance = await store.debit_balance("t1", 0, "lease")
        assert balance == 500
        # No ledger row appended for a zero debit.
        assert await store.get_balance("t1") == 500
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# Payments: provider seam + promo
# ---------------------------------------------------------------------------


async def test_get_provider_fail_closed():
    assert get_provider("stub").name == "stub"
    with pytest.raises(PaymentError):
        get_provider("stripe")


def test_compute_promo_first_order_only():
    assert compute_promo(1000, 20, True) == 200
    assert compute_promo(1000, 20, False) == 0
    assert compute_promo(1000, 0, True) == 0


# ---------------------------------------------------------------------------
# HTTP routes (service-token gated admin recharge plane)
# ---------------------------------------------------------------------------


async def test_recharge_routes_end_to_end():
    store = InMemoryStore()
    await store.connect()
    try:
        await store.create_tenant("t1", display_name="T1")
        client, _s = _client(store)
        with client:
            # First order carries the first-purchase promo (default 20%).
            r = client.post(
                "/api/v1/admin/tenants/t1/recharge/orders", json={"tokens": 1000}, headers=AUTH
            )
            assert r.status_code == 200, r.text
            order = r.json()
            assert order["promo_tokens"] == 200
            assert order["status"] == "created"

            r = client.get("/api/v1/admin/tenants/t1/recharge/balance", headers=AUTH)
            assert r.json()["balance"] == 0

            r = client.post(
                f"/api/v1/admin/tenants/t1/recharge/orders/{order['order_id']}/pay", headers=AUTH
            )
            assert r.status_code == 200, r.text
            assert r.json()["status"] == "paid"
            assert r.json()["provider_ref"].startswith("stub_")

            r = client.get("/api/v1/admin/tenants/t1/recharge/balance", headers=AUTH)
            assert r.json()["balance"] == 1200

            # Idempotent replay does not double-credit.
            r = client.post(
                f"/api/v1/admin/tenants/t1/recharge/orders/{order['order_id']}/pay", headers=AUTH
            )
            assert r.status_code == 200
            r = client.get("/api/v1/admin/tenants/t1/recharge/balance", headers=AUTH)
            assert r.json()["balance"] == 1200

            # Second order: promo applies once per tenant.
            r = client.post(
                "/api/v1/admin/tenants/t1/recharge/orders", json={"tokens": 1000}, headers=AUTH
            )
            assert r.json()["promo_tokens"] == 0
            oid2 = r.json()["order_id"]
            r = client.post(f"/api/v1/admin/tenants/t1/recharge/orders/{oid2}/pay", headers=AUTH)
            assert r.status_code == 200
            r = client.get("/api/v1/admin/tenants/t1/recharge/balance", headers=AUTH)
            assert r.json()["balance"] == 2200

            # Order inventory + single fetch.
            r = client.get("/api/v1/admin/tenants/t1/recharge/orders", headers=AUTH)
            assert len(r.json()) == 2
            r = client.get(
                f"/api/v1/admin/tenants/t1/recharge/orders/{order['order_id']}", headers=AUTH
            )
            assert r.json()["status"] == "paid"
    finally:
        await store.close()


async def test_recharge_route_guards():
    store = InMemoryStore()
    await store.connect()
    try:
        await store.create_tenant("t1", display_name="T1")
        client, _s = _client(store)
        with client:
            # No auth header -> 401 (service-token gate).
            r = client.post("/api/v1/admin/tenants/t1/recharge/orders", json={"tokens": 100})
            assert r.status_code == 401
            # Unknown tenant -> 404.
            r = client.post(
                "/api/v1/admin/tenants/ghost/recharge/orders", json={"tokens": 100}, headers=AUTH
            )
            assert r.status_code == 404
            # Unknown order -> 404.
            r = client.post("/api/v1/admin/tenants/t1/recharge/orders/pre_nope/pay", headers=AUTH)
            assert r.status_code == 404
            # Cross-tenant order fetch denied.
            r = client.post(
                "/api/v1/admin/tenants/t1/recharge/orders", json={"tokens": 100}, headers=AUTH
            )
            oid = r.json()["order_id"]
            await store.create_tenant("t2", display_name="T2")
            r = client.get(f"/api/v1/admin/tenants/t2/recharge/orders/{oid}", headers=AUTH)
            assert r.status_code == 404
            # Invalid body -> 422.
            r = client.post(
                "/api/v1/admin/tenants/t1/recharge/orders", json={"tokens": 0}, headers=AUTH
            )
            assert r.status_code == 422
    finally:
        await store.close()


async def test_recharge_unknown_provider_fail_closed():
    store = InMemoryStore()
    await store.connect()
    try:
        await store.create_tenant("t1", display_name="T1")
        client, _s = _client(store, payment_provider="acme-pay")
        with client:
            r = client.post(
                "/api/v1/admin/tenants/t1/recharge/orders", json={"tokens": 100}, headers=AUTH
            )
            assert r.status_code == 503
            assert "unknown payment provider" in r.json()["detail"]
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# gRPC enforcement: free quota first, balance covers overflow, recharge unblocks
# ---------------------------------------------------------------------------


@pytest.fixture
async def prepaid_stack():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = InMemoryStore()
    await store.connect()
    concurrency = ConcurrencyManager(redis, 120)
    await concurrency.init_scripts()
    cache = IdentityCache(redis)
    await cache.init_scripts()
    servicer = IdentityServiceServicer(store=store, cache=cache, concurrency=concurrency)
    server = grpc.aio.server()
    pb_grpc.add_IdentityServiceServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    channel = grpc.aio.insecure_channel(f"127.0.0.1:{port}")
    stub = pb_grpc.IdentityServiceStub(channel)

    await store.create_tenant("pt1", display_name="PT1")
    raw, _ = await store.create_api_key("pt1", None, scopes=["inference"])
    await store.put_quota("pt1", concurrent=5, tpm=1000, allowed_modules=[])
    try:
        yield SimpleNamespace(store=store, stub=stub, raw_key=raw)
    finally:
        await channel.close()
        await server.stop(grace=None)
        await store.close()


async def _authorize(stub, raw_key: str):
    return await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw_key, target_module="office", target_model="", request_id="r74"
        )
    )


async def test_free_quota_then_balance_exhausted_then_recharge_unblocks(prepaid_stack):
    ns = prepaid_stack
    # Free daily quota (tpm=1000) covers the first reports.
    resp = await _authorize(ns.stub, ns.raw_key)
    assert resp.is_allowed, pb_msg(resp)
    usage = await ns.stub.ReportUsage(
        pb.ReportUsageRequest(
            lease_id=resp.lease_id,
            tenant_id="pt1",
            model_name="m",
            prompt_tokens=600,
            completion_tokens=0,
            release_after=True,
        )
    )
    assert usage.success is True
    assert usage.remaining_balance == 0

    resp2 = await _authorize(ns.stub, ns.raw_key)
    assert resp2.is_allowed, pb_msg(resp2)
    usage2 = await ns.stub.ReportUsage(
        pb.ReportUsageRequest(
            lease_id=resp2.lease_id,
            tenant_id="pt1",
            model_name="m",
            prompt_tokens=600,
            completion_tokens=0,
            release_after=True,
        )
    )
    # used_before=600, used_after=1200, limit=1000 -> overflow debit = 200.
    assert usage2.remaining_balance == -200

    # Daily quota gone AND balance <= 0 -> BALANCE_EXHAUSTED.
    resp3 = await _authorize(ns.stub, ns.raw_key)
    assert not resp3.is_allowed
    assert resp3.error_code == pb.AuthErrorCode.BALANCE_EXHAUSTED

    # Recharge (no promo — store-level path): same key unblocks immediately.
    order = await ns.store.create_prepaid_order("pt1", 1000, 0, "stub")
    await ns.store.mark_prepaid_order_paid(order["order_id"], "ref")
    assert await ns.store.get_balance("pt1") == 800
    resp4 = await _authorize(ns.stub, ns.raw_key)
    assert resp4.is_allowed, pb_msg(resp4)
    usage4 = await ns.stub.ReportUsage(
        pb.ReportUsageRequest(
            lease_id=resp4.lease_id,
            tenant_id="pt1",
            model_name="m",
            prompt_tokens=100,
            completion_tokens=0,
            release_after=True,
        )
    )
    # used_before=1200 (200 already debited as debt), +100=1300 ->
    # overflow delta = 300-200 = 100 -> balance 800-100=700.
    assert usage4.remaining_balance == 700


async def test_balance_covers_overflow_when_daily_quota_exhausted(prepaid_stack):
    ns = prepaid_stack
    await ns.store.create_prepaid_order("pt1", 10000, 0, "stub")
    orders = await ns.store.list_prepaid_orders("pt1")
    await ns.store.mark_prepaid_order_paid(orders[0]["order_id"], "ref")
    resp = await _authorize(ns.stub, ns.raw_key)
    assert resp.is_allowed, pb_msg(resp)
    usage = await ns.stub.ReportUsage(
        pb.ReportUsageRequest(
            lease_id=resp.lease_id,
            tenant_id="pt1",
            model_name="m",
            prompt_tokens=1000,
            completion_tokens=0,
            release_after=True,
        )
    )
    assert usage.success is True
    assert usage.remaining_balance == 10000
    # Daily quota now exhausted, but balance > 0 keeps authorizing.
    resp2 = await _authorize(ns.stub, ns.raw_key)
    assert resp2.is_allowed, pb_msg(resp2)
    await ns.stub.ReportUsage(
        pb.ReportUsageRequest(
            lease_id=resp2.lease_id,
            tenant_id="pt1",
            model_name="m",
            prompt_tokens=100,
            completion_tokens=0,
            release_after=True,
        )
    )
    resp3 = await _authorize(ns.stub, ns.raw_key)
    assert resp3.is_allowed, "positive balance must cover post-quota overflow"


def pb_msg(resp) -> str:
    return pb.AuthErrorCode.Name(resp.error_code) + ": " + resp.error_message
