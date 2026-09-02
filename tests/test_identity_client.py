from __future__ import annotations

import fakeredis.aioredis
import grpc
import pytest

from fusion_identity.client.identity_client import IdentityClient
from fusion_identity.client.lease_guard import LeaseDenied, lease_guard
from fusion_identity.concurrency import ConcurrencyManager
from fusion_identity.grpc import identity_pb2_grpc as pb_grpc
from fusion_identity.grpc_servicer import IdentityServiceServicer
from fusion_identity.store import InMemoryStore


async def _seed(store: InMemoryStore, tenant_id: str = "acme", plan: str = "enterprise") -> str:
    await store.create_tenant(tenant_id, display_name=tenant_id, plan=plan)
    await store.create_user(user_id="u1", username="u1", password="pw12345678", email=None)
    await store.add_member(tenant_id, "u1", role="tenant_admin", added_by="seed")
    raw, _ = await store.create_api_key(tenant_id, "u1", scopes=["inference"])
    return raw


@pytest.fixture
async def client_stack():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = InMemoryStore()
    await store.connect()
    concurrency = ConcurrencyManager(redis, 120)
    await concurrency.init_scripts()
    from fusion_identity.cache import IdentityCache

    cache = IdentityCache(redis)
    servicer = IdentityServiceServicer(store=store, cache=cache, concurrency=concurrency)
    server = grpc.aio.server()
    pb_grpc.add_IdentityServiceServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    client = IdentityClient(target=f"127.0.0.1:{port}", deadline_ms=500)
    await client.connect()
    try:
        yield store, client
    finally:
        await client.close()
        await server.stop(grace=None)
        await store.close()


async def test_client_authorize(client_stack):
    store, client = client_stack
    raw = await _seed(store)
    resp = await client.authorize_and_acquire(
        api_key=raw, target_module="code", target_model="qwen", request_id="c1"
    )
    assert resp.is_allowed is True
    assert resp.lease_id


async def test_client_invalid_key(client_stack):
    _store, client = client_stack
    resp = await client.authorize_and_acquire(
        api_key="fmu_bad", target_module="code", request_id="c2"
    )
    assert resp.is_allowed is False


async def test_client_release_and_report(client_stack):
    store, client = client_stack
    raw = await _seed(store)
    resp = await client.authorize_and_acquire(api_key=raw, target_module="code", request_id="c3")
    ok = await client.release_lease(resp.lease_id, resp.tenant_context.tenant_id, "done")
    assert ok is True
    usage = await client.report_usage(
        lease_id=resp.lease_id,
        tenant_id=resp.tenant_context.tenant_id,
        model_name="qwen",
        prompt_tokens=10,
        completion_tokens=5,
    )
    assert usage is not None
    assert usage.success is True


async def test_lease_guard_success(client_stack):
    store, client = client_stack
    raw = await _seed(store)
    async with lease_guard(client, raw, "code", "qwen", "g1") as resp:
        assert resp.is_allowed is True
        assert resp.lease_id


async def test_lease_guard_denied(client_stack):
    _store, client = client_stack
    with pytest.raises(LeaseDenied):
        async with lease_guard(client, "fmu_bad", "code", "", "g2"):
            pass
