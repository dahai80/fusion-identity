from __future__ import annotations

from types import SimpleNamespace

import fakeredis.aioredis
import grpc
import pytest

from fusion_identity.cache import IdentityCache
from fusion_identity.concurrency import ConcurrencyManager
from fusion_identity.grpc import identity_pb2 as pb
from fusion_identity.grpc import identity_pb2_grpc as pb_grpc
from fusion_identity.grpc_servicer import IdentityServiceServicer
from fusion_identity.store import InMemoryStore

SERVICE_TOKEN = "test-service-token-s3cr3t-s3cr3t"


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
    cache = IdentityCache(redis)
    await cache.init_scripts()
    servicer = IdentityServiceServicer(store=store, cache=cache, concurrency=concurrency)
    server = grpc.aio.server()
    pb_grpc.add_IdentityServiceServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    channel = grpc.aio.insecure_channel(f"127.0.0.1:{port}")
    stub = pb_grpc.IdentityServiceStub(channel)
    try:
        yield store, stub, servicer
    finally:
        await channel.close()
        await server.stop(grace=None)
        await store.close()


async def test_authorize_pass(grpc_stack):
    store, stub, _ = grpc_stack
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
    _store, stub, _ = grpc_stack
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key="fmu_bogus", target_module="code", target_model="", request_id="r2"
        )
    )
    assert resp.is_allowed is False
    assert resp.error_code == pb.AuthErrorCode.INVALID_API_KEY


async def test_authorize_concurrency_limit(grpc_stack):
    store, stub, _ = grpc_stack
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
    # T6: a rejected acquire must not corrupt the counter.
    assert await grpc_stack[2]._concurrency.active_count("acme") == 1


async def test_release_and_reacquire(grpc_stack):
    store, stub, _ = grpc_stack
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


async def test_cross_tenant_release_rejected(grpc_stack):
    # T4/L5: releasing another tenant's lease must fail.
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r5b"
        )
    )
    rel = await stub.ReleaseLease(
        pb.ReleaseLeaseRequest(lease_id=resp.lease_id, tenant_id="other", reason="attack")
    )
    assert rel.success is False


async def test_cross_tenant_usage_rejected(grpc_stack):
    # T4/L6: reporting usage under a victim tenant_id must not poison quota.
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r5c"
        )
    )
    usage = await stub.ReportUsage(
        pb.ReportUsageRequest(
            lease_id=resp.lease_id,
            tenant_id="victim",
            model_name="qwen",
            prompt_tokens=999999,
            completion_tokens=0,
        )
    )
    assert usage.success is False


async def test_report_usage_no_implicit_release(grpc_stack):
    # T7/L7: ReportUsage must NOT release the lease unless release_after is set.
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    await store.put_quota("acme", concurrent=1)
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r7"
        )
    )
    usage = await stub.ReportUsage(
        pb.ReportUsageRequest(
            lease_id=resp.lease_id,
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
    # Lease still held: a new acquire must be denied.
    resp2 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r7b"
        )
    )
    assert resp2.is_allowed is False


async def test_report_usage_release_after(grpc_stack):
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    await store.put_quota("acme", concurrent=1)
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r7c"
        )
    )
    usage = await stub.ReportUsage(
        pb.ReportUsageRequest(
            lease_id=resp.lease_id,
            tenant_id="acme",
            model_name="qwen",
            prompt_tokens=10,
            completion_tokens=5,
            release_after=True,
        )
    )
    assert usage.success is True
    resp2 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", target_model="", request_id="r7d"
        )
    )
    assert resp2.is_allowed is True


async def test_rpm_boundary_rejects_over_limit(grpc_stack):
    # T2/L3: with rpm=N, the Nth call is allowed and the N+1th is refused
    # with RATE_LIMIT_EXCEEDED.
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    await store.put_quota("acme", rpm=2)
    r1 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(api_key=raw, target_module="code", request_id="rpm1")
    )
    assert r1.is_allowed is True, r1
    await stub.ReleaseLease(pb.ReleaseLeaseRequest(lease_id=r1.lease_id, tenant_id="acme"))
    r2 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(api_key=raw, target_module="code", request_id="rpm2")
    )
    assert r2.is_allowed is True, r2
    await stub.ReleaseLease(pb.ReleaseLeaseRequest(lease_id=r2.lease_id, tenant_id="acme"))
    r3 = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(api_key=raw, target_module="code", request_id="rpm3")
    )
    assert r3.is_allowed is False, r3
    assert r3.error_code == pb.AuthErrorCode.RATE_LIMIT_EXCEEDED


async def test_concurrency_rejected_does_not_burn_rpm(grpc_stack):
    # T2/L3: a concurrency-limit rejection must NOT consume the rpm budget.
    # concurrent=1, acquire one lease (holds the single slot), then attempt K
    # more — each denied with CONCURRENCY_LIMIT_EXCEEDED. Those denials must
    # not have touched the rpm counter: after releasing, an authorize still
    # succeeds within the small rpm budget.
    store, stub, servicer = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    await store.put_quota("acme", concurrent=1, rpm=3)
    held = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(api_key=raw, target_module="code", request_id="hold")
    )
    assert held.is_allowed is True
    for i in range(4):
        r = await stub.AuthorizeAndAcquire(
            pb.AuthorizeAndAcquireRequest(api_key=raw, target_module="code", request_id=f"cx{i}")
        )
        assert r.is_allowed is False, r
        assert r.error_code == pb.AuthErrorCode.CONCURRENCY_LIMIT_EXCEEDED
    # release the held slot; rpm untouched by the 4 denials (limit 3) → allowed.
    await stub.ReleaseLease(pb.ReleaseLeaseRequest(lease_id=held.lease_id, tenant_id="acme"))
    await servicer._cache.invalidate_tenant("acme")
    ok = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(api_key=raw, target_module="code", request_id="cxok")
    )
    assert ok.is_allowed is True, ok


async def test_quota_zero_concurrent_denies_not_default(grpc_stack):
    # P0-3: concurrent=0 means "stop inference", NOT default 2.
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "zeroc", "usr_zeroc")
    await store.put_quota("zeroc", concurrent=0)
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(api_key=raw, target_module="code", request_id="z1")
    )
    assert resp.is_allowed is False
    assert resp.error_code == pb.AuthErrorCode.CONCURRENCY_LIMIT_EXCEEDED


async def test_quota_zero_tpm_denies_not_default(grpc_stack):
    # P0-3: tpm=0 means "no daily token budget", NOT default 50000.
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "zerot", "usr_zerot")
    await store.put_quota("zerot", concurrent=4, tpm=0)
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(api_key=raw, target_module="code", request_id="z2")
    )
    assert resp.is_allowed is False
    assert resp.error_code == pb.AuthErrorCode.DAILY_QUOTA_EXCEEDED


async def test_p2_3_authorize_cross_tenant_assertion_refused(grpc_stack):
    # P2-3: a caller asserting the wrong tenant for an api_key must be refused
    # (fail-closed), so a key for tenant A cannot be misattributed to tenant B.
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", request_id="p23x", tenant_id="other"
        )
    )
    assert resp.is_allowed is False
    assert resp.error_code == pb.AuthErrorCode.INVALID_API_KEY


async def test_p2_3_authorize_matching_tenant_assertion_passes(grpc_stack):
    # P2-3: asserting the correct tenant matches the key's real tenant → allowed,
    # parity with the unasserted path.
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    resp = await stub.AuthorizeAndAcquire(
        pb.AuthorizeAndAcquireRequest(
            api_key=raw, target_module="code", request_id="p23ok", tenant_id="acme"
        )
    )
    assert resp.is_allowed is True
    assert resp.tenant_context.tenant_id == "acme"


async def test_grpc_service_token_interceptor_rejects_unauth():
    # T5/F1: a server wired with the interceptor rejects missing/invalid token.
    from fusion_identity.grpc_interceptor import ServiceTokenInterceptor

    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = InMemoryStore()
    await store.connect()
    concurrency = ConcurrencyManager(redis, 120)
    await concurrency.init_scripts()
    cache = IdentityCache(redis)
    await cache.init_scripts()
    servicer = IdentityServiceServicer(store=store, cache=cache, concurrency=concurrency)
    app = SimpleNamespace(
        state=SimpleNamespace(
            store=store,
            cache=cache,
            concurrency=concurrency,
            settings=SimpleNamespace(service_token=SERVICE_TOKEN),
        )
    )
    interceptor = ServiceTokenInterceptor(SERVICE_TOKEN)
    server = grpc.aio.server(interceptors=[interceptor])
    pb_grpc.add_IdentityServiceServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    channel = grpc.aio.insecure_channel(f"127.0.0.1:{port}")
    stub = pb_grpc.IdentityServiceStub(channel)
    try:
        with pytest.raises(grpc.aio.AioRpcError) as exc_no_token:
            await stub.AuthorizeAndAcquire(
                pb.AuthorizeAndAcquireRequest(api_key="x", target_module="code")
            )
        assert exc_no_token.value.code() == grpc.StatusCode.UNAUTHENTICATED
        with pytest.raises(grpc.aio.AioRpcError) as exc_bad_token:
            await stub.AuthorizeAndAcquire(
                pb.AuthorizeAndAcquireRequest(api_key="x", target_module="code"),
                metadata=[("x-fusion-service-token", "wrong")],
            )
        assert exc_bad_token.value.code() == grpc.StatusCode.UNAUTHENTICATED
        raw = await _seed_key(store, "acme", "usr_acme")
        resp = await stub.AuthorizeAndAcquire(
            pb.AuthorizeAndAcquireRequest(api_key=raw, target_module="code"),
            metadata=[("x-fusion-service-token", SERVICE_TOKEN)],
        )
        assert resp.is_allowed is True
    finally:
        await channel.close()
        await server.stop(grace=None)
        await store.close()
        _ = app
