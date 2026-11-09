from __future__ import annotations

import httpx
import pytest

from fusion_identity import billing
from fusion_identity.cache import IdentityCache
from fusion_identity.concurrency import ConcurrencyManager
from fusion_identity.grpc import identity_pb2 as pb
from fusion_identity.grpc import identity_pb2_grpc as pb_grpc
from fusion_identity.grpc_servicer import IdentityServiceServicer
from fusion_identity.store import InMemoryStore


@pytest.fixture
async def grpc_stack():
    import fakeredis.aioredis
    import grpc

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


async def _seed_key(store: InMemoryStore, tenant_id: str, user_id: str) -> str:
    await store.create_tenant(tenant_id, display_name=tenant_id, plan="enterprise")
    await store.create_user(user_id=user_id, username=user_id, password="pw12345678", email=None)
    await store.add_member(tenant_id, user_id, role="tenant_admin", added_by="seed")
    raw, _ = await store.create_api_key(tenant_id, user_id, scopes=["inference"])
    return raw


@pytest.fixture
async def billing_env(monkeypatch):
    def install(handler, fail_mode="open"):
        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, timeout=2.0, base_url="http://billing.test")

        def fake_get_async_client(base_url, **kwargs):
            return client

        monkeypatch.setattr(billing, "get_async_client", fake_get_async_client)
        monkeypatch.setenv("FUSION_IDENTITY_BILLING_URL", "http://billing.test")
        monkeypatch.setenv("FUSION_IDENTITY_BILLING_TOKEN", "tok-123")
        monkeypatch.setenv("FUSION_IDENTITY_BILLING_FAIL_MODE", fail_mode)

    yield install
    monkeypatch.delenv("FUSION_IDENTITY_BILLING_URL", raising=False)
    monkeypatch.delenv("FUSION_IDENTITY_BILLING_TOKEN", raising=False)
    monkeypatch.delenv("FUSION_IDENTITY_BILLING_FAIL_MODE", raising=False)


def _authorize_kwargs(raw: str) -> dict:
    return dict(
        api_key=raw,
        target_module="code",
        target_model="qwen",
        request_id="r-billing",
    )


async def test_billing_disabled_by_default(grpc_stack, billing_env):
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    called = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request.url.path)
        return httpx.Response(200, json={"granted": True})

    billing_env(handler)
    import os

    os.environ.pop("FUSION_IDENTITY_BILLING_URL")
    resp = await stub.AuthorizeAndAcquire(pb.AuthorizeAndAcquireRequest(**_authorize_kwargs(raw)))
    assert resp.is_allowed is True
    assert called == []


async def test_billing_granted_proceeds(grpc_stack, billing_env):
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        seen["tenant"] = request.headers.get("x-fusion-tenant")
        import json

        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"granted": True, "remaining": 900})

    billing_env(handler)
    resp = await stub.AuthorizeAndAcquire(pb.AuthorizeAndAcquireRequest(**_authorize_kwargs(raw)))
    assert resp.is_allowed is True
    assert seen["path"] == "/api/wallet/consume"
    assert seen["auth"] == "Bearer tok-123"
    assert seen["tenant"] == "acme"
    assert seen["body"]["ref_id"] == resp.lease_id
    assert seen["body"]["amount"] == resp.max_allowed_tokens


async def test_billing_402_refuses_and_releases_lease(grpc_stack, billing_env):
    store, stub, servicer = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, json={"error": "quota_exhausted"})

    billing_env(handler)
    resp = await stub.AuthorizeAndAcquire(pb.AuthorizeAndAcquireRequest(**_authorize_kwargs(raw)))
    assert resp.is_allowed is False
    assert resp.error_code == pb.AuthErrorCode.DAILY_QUOTA_EXCEEDED
    assert "wallet" in resp.error_message
    # lease released: active concurrency is back to zero
    active = await servicer._concurrency.active_count("acme")
    assert active == 0
    # daily quota refunded: a later authorize (billing disabled) still passes
    import os

    os.environ.pop("FUSION_IDENTITY_BILLING_URL")
    resp2 = await stub.AuthorizeAndAcquire(pb.AuthorizeAndAcquireRequest(**_authorize_kwargs(raw)))
    assert resp2.is_allowed is True


async def test_billing_unreachable_fail_open(grpc_stack, billing_env):
    store, stub, _ = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    billing_env(handler, fail_mode="open")
    resp = await stub.AuthorizeAndAcquire(pb.AuthorizeAndAcquireRequest(**_authorize_kwargs(raw)))
    assert resp.is_allowed is True


async def test_billing_unreachable_fail_closed(grpc_stack, billing_env):
    store, stub, servicer = grpc_stack
    raw = await _seed_key(store, "acme", "usr_acme")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    billing_env(handler, fail_mode="closed")
    resp = await stub.AuthorizeAndAcquire(pb.AuthorizeAndAcquireRequest(**_authorize_kwargs(raw)))
    assert resp.is_allowed is False
    assert resp.error_code == pb.AuthErrorCode.DAILY_QUOTA_EXCEEDED
    active = await servicer._concurrency.active_count("acme")
    assert active == 0
