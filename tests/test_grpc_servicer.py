from __future__ import annotations

import fakeredis.aioredis
import grpc
import pytest

from fusion_identity.concurrency import ConcurrencyManager
from fusion_identity.grpc import identity_pb2 as pb
from fusion_identity.grpc import identity_pb2_grpc as pb_grpc
from fusion_identity.grpc_servicer import IdentityServiceServicer
from fusion_identity.store import InMemoryStore


async def _seed_key(store: InMemoryStore, tenant_id: str, user_id: str) -> str:
    await store.create_tenant(tenant_id, display_name=tenant_id, plan="enterprise")
    await store.create_user(user_id=user_id, username=user_id, password="pw12345678", email=None)
    await store.add_member(tenant_id, user_id, role="tenant_admin", added_by="seed")
    raw, _ = await store.create_api_key(tenant_id, user_id, scopes=["inference"])
    return raw


@pytest.fixture
async def grpc_stack():
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
    channel = grpc.aio.insecure_channel(f"127.0.0.1:{port}")
    stub = pb_grpc.IdentityServiceStub(channel)
    try:
        yield store, stub
    finally:
        await channel.close()
        await server.stop(grace=None)
        await store.close()


async def test_authorize_pass(grpc_stack):
    store, stub = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="qwen", request_id="r1"
        )
    )
    assert resp.is_allowed is True
    assert resp.lease_id
    assert resp.tenant_context.tenant_id == "acme"
    assert resp.tenant_context.priority == 3
    assert resp.max_allowed_tokens > 0


async def test_authorize_invalid_key(grpc_stack):
    _store, stub = grpc_stack
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key="fmu_bogus", target_module="code", target_model="", request_id="r2"
        )
    )
    assert resp.is_allowed is False
    assert resp.error_code == pb.AuthErrorCode.INVALID_API_KEY


async def test_authorize_concurrency_limit(grpc_stack):
    store, stub = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    await store.put_quota("acme", concurrent=1)
    resp1 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r3"
        )
    )
    assert resp1.is_allowed is True
    resp2 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r4"
        )
    )
    assert resp2.is_allowed is False
    assert resp2.error_code == pb.AuthErrorCode.CONCURRENCY_LIMIT_EXCEEDED


async def test_release_and_reacquire(grpc_stack):
    store, stub = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    await store.put_quota("acme", concurrent=1)
    resp1 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r5"
        )
    )
    rel = await stub.ReleaseLease(
        pb.ReleaseLeaseRequest(lease_id=resp1.lease_id, tenant_id="acme", reason="done")
    )
    assert rel.success is True
    resp2 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r6"
        )
    )
    assert resp2.is_allowed is True


async def test_report_usage(grpc_stack):
    store, stub = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    resp1 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r7"
        )
    )
    usage = await stub.ReportUsage(
        pb.ReportUsageRequest(
            lease_id=resp1.lease_id,
            tenant_id="acme",
            model_name="qwen",
            prompt_tokens=100,
            completion_tokens=50,
            execution_time_ms=200,
            status=pb.InferenceStatus.SUCCESS,
        )
    )
    assert usage.success is True
    assert usage.remaining_daily_quota >= 0
