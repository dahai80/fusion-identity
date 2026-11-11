from __future__ import annotations

import contextlib
import os
import subprocess
from pathlib import Path

import pytest

from tests.test_start_registry_check import _BASE_ENV, START_SH

logger = __import__("logging").getLogger(__name__)

_REDIS_URL = "redis://127.0.0.1:6379/0"
_GRPC_PORT = "50051"


def _run_trace(extra_env: dict[str, str]) -> str:
    # bash -x prints every executed command (incl. our exports) on stderr.
    env = dict(os.environ)
    env.update(_BASE_ENV)
    env["FUSION_REGISTRY"] = str(Path(os.devnull).parent / "nonexistent-registry.yaml")
    env["FUSION_SKIP_REGISTRY_CHECK"] = "1"
    # /dev/null sources as nothing — the persisted operator env file
    # (~/.fusion-identity/env now carries the enforcement vars) must not
    # leak into a test of the UNSET defaults.
    env["FUSION_IDENTITY_ENV_FILE"] = os.devnull
    for var in ("FUSION_IDENTITY_REDIS_URL", "FUSION_IDENTITY_GRPC_PORT"):
        env.pop(var, None)
    env.update(extra_env)
    result = subprocess.run(
        ["bash", "-x", str(START_SH), "registry-check"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    return result.stderr


def test_start_sh_defaults_enforcement_plane_on():
    # Issue #71: with neither var set (the state that left prod's enforcement
    # plane dark), start.sh must default redis + gRPC ON.
    trace = _run_trace({})
    assert f"export FUSION_IDENTITY_REDIS_URL={_REDIS_URL}" in trace
    assert f"export FUSION_IDENTITY_GRPC_PORT={_GRPC_PORT}" in trace


def test_start_sh_opt_out_set_but_empty_redis():
    # Opt-out contract: set-but-empty redis URL stays empty (enforcement off)
    # — ${VAR+set} must distinguish "exported as empty" from "never set".
    trace = _run_trace({"FUSION_IDENTITY_REDIS_URL": ""})
    # set-but-empty: no export fires, the empty value survives untouched
    assert "export FUSION_IDENTITY_REDIS_URL" not in trace


def test_start_sh_explicit_values_preserved():
    # Operator-provided values are never overwritten — the default export
    # lines never fire when the vars are already set.
    trace = _run_trace(
        {
            "FUSION_IDENTITY_REDIS_URL": "redis://10.0.0.9:6380/3",
            "FUSION_IDENTITY_GRPC_PORT": "50099",
        }
    )
    assert "export FUSION_IDENTITY_REDIS_URL=" not in trace
    assert "export FUSION_IDENTITY_GRPC_PORT=" not in trace


def test_start_sh_persists_enforcement_vars_for_restart():
    # Issue #64 env persistence must cover the enforcement plane too, or a
    # clean-shell restart silently re-disables it (the exact #71 regression).
    source = START_SH.read_text(encoding="utf-8")
    assert "FUSION_IDENTITY_REDIS_URL FUSION_IDENTITY_GRPC_PORT" in source


# ---------------------------------------------------------------------------
# Live enforcement-chain acceptance (real PG + real redis + real gRPC socket)
# ---------------------------------------------------------------------------

PG_URL = os.environ.get(
    "FUSION_IDENTITY_DATABASE_URL",
    "postgresql://postgres:pgpassword@127.0.0.1:5433/fusion_identity",
)
_TEST_GRPC_PORT = 51477
_TENANT = "pgenforce71"


@pytest.fixture
async def enforce_stack():
    # The grpc.aio server must live on the SAME event loop as the PgStore pool
    # (asyncpg is loop-bound) — start serve_grpc directly instead of going
    # through TestClient, whose portal runs the app on a second loop.
    from types import SimpleNamespace

    import redis.asyncio as aioredis

    from fusion_identity.cache import IdentityCache
    from fusion_identity.concurrency import ConcurrencyManager
    from fusion_identity.db import PgStore
    from fusion_identity.grpc_server import serve as serve_grpc
    from fusion_identity.store import sha256_hash
    from tests.conftest import _settings

    store = PgStore(PG_URL)
    await store.connect()
    await store.ensure_schema()
    # FK-ordered cleanup of any leftover from a crashed prior run.
    for sql in (
        "DELETE FROM event_outbox WHERE tenant_id=$1",
        "DELETE FROM usage_ledger WHERE tenant_id=$1",
        "DELETE FROM lease_log WHERE tenant_id=$1",
        "DELETE FROM api_keys WHERE tenant_id=$1",
        "DELETE FROM quotas WHERE tenant_id=$1",
        "DELETE FROM tenant_members WHERE tenant_id=$1",
        "DELETE FROM tenants WHERE tenant_id=$1",
    ):
        with contextlib.suppress(Exception):
            await store.execute(sql, _TENANT)
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM tenants WHERE tenant_id=$1", _TENANT)

    await store.create_tenant(_TENANT, "Issue 71 Enforcement")
    raw_key, _row = await store.create_api_key(_TENANT, None, ["inference"])
    await store.put_quota(_TENANT, concurrent=2, tpm=100000, allowed_modules=[])

    rclient = aioredis.from_url(_REDIS_URL, decode_responses=True)
    # scrub any stale counters for the test tenant (IdentityCache keys carry
    # no namespace prefix: quota:{tid}:{day}, leases:{tid}, apikey:{sha256}).
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
        state=SimpleNamespace(
            settings=s,
            store=store,
            cache=cache,
            concurrency=concurrency,
        )
    )
    server = await serve_grpc(fake_app, host="127.0.0.1", port=_TEST_GRPC_PORT)
    ns = SimpleNamespace(
        store=store,
        redis=rclient,
        cache=cache,
        concurrency=concurrency,
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
    for sql in (
        "DELETE FROM event_outbox WHERE tenant_id=$1",
        "DELETE FROM usage_ledger WHERE tenant_id=$1",
        "DELETE FROM lease_log WHERE tenant_id=$1",
        "DELETE FROM api_keys WHERE tenant_id=$1",
        "DELETE FROM quotas WHERE tenant_id=$1",
        "DELETE FROM tenant_members WHERE tenant_id=$1",
        "DELETE FROM tenants WHERE tenant_id=$1",
    ):
        with contextlib.suppress(Exception):
            await store.execute(sql, _TENANT)
    await store.close()


@pytest.mark.integration
async def test_enforcement_chain_authorizes_tenant_key(enforce_stack):
    # Issue #71 acceptance: a tenant fmu_ key authorizes over the real gRPC
    # socket, a lease is acquired, and the daily-quota counter moves.
    from fusion_identity.client.identity_client import IdentityClient

    ic = IdentityClient(
        target=f"127.0.0.1:{_TEST_GRPC_PORT}",
        deadline_ms=2000,
        service_token=enforce_stack.service_token,
    )
    try:
        assert await ic.health() is True
        resp = await ic.authorize_and_acquire(enforce_stack.raw_key, "office")
        assert resp.is_allowed, pb_msg(resp)
        assert resp.lease_id
        assert resp.tenant_context.tenant_id == _TENANT

        # reserve_daily_quota only reserves a 0-token placeholder — the
        # counter moves on ReportUsage.
        import time

        usage = await ic.report_usage(
            resp.lease_id, _TENANT, "test-model", prompt_tokens=10, completion_tokens=5
        )
        assert usage is not None, "report_usage failed"
        used = await enforce_stack.redis.get(f"quota:{_TENANT}:{time.strftime('%Y-%m-%d')}")
        assert used is not None and int(used) >= 15, "daily-quota counter did not move"
        remaining = await enforce_stack.cache.remaining_quota(_TENANT, 100000)
        assert remaining <= 100000 - 15, remaining

        released = await ic.release_lease(resp.lease_id, _TENANT)
        assert released is True
    finally:
        await ic.close()


@pytest.mark.integration
async def test_enforcement_chain_concurrency_limit_429(enforce_stack):
    # Issue #71 acceptance: concurrent=1 makes the SECOND parallel authorize
    # fail with CONCURRENCY_LIMIT_EXCEEDED (HTTP-mapped 429).
    from fusion_identity.client.identity_client import IdentityClient
    from fusion_identity.grpc import identity_pb2 as pb

    await enforce_stack.store.put_quota(_TENANT, concurrent=1)
    ic = IdentityClient(
        target=f"127.0.0.1:{_TEST_GRPC_PORT}",
        deadline_ms=2000,
        service_token=enforce_stack.service_token,
    )
    try:
        first = await ic.authorize_and_acquire(enforce_stack.raw_key, "office")
        assert first.is_allowed, pb_msg(first)
        second = await ic.authorize_and_acquire(enforce_stack.raw_key, "office")
        assert not second.is_allowed
        assert second.error_code == pb.AuthErrorCode.CONCURRENCY_LIMIT_EXCEEDED
        # release the lease -> the next acquire goes through again
        await ic.release_lease(first.lease_id, _TENANT)
        third = await ic.authorize_and_acquire(enforce_stack.raw_key, "office")
        assert third.is_allowed, pb_msg(third)
        await ic.release_lease(third.lease_id, _TENANT)
    finally:
        await ic.close()


@pytest.mark.integration
async def test_admin_quota_tighten_invalidates_apikey_cache(enforce_stack):
    # Issue #71 regression: the admin-plane PUT /tenants/{id} only dropped the
    # tenant cache blob, NOT the per-api-key blobs that embed max_concurrency
    # — a quota tighten via the admin path left the gRPC plane enforcing the
    # stale lenient quota for up to 300s (routes/quotas.py already did it).
    import dataclasses

    from starlette.testclient import TestClient

    from fusion_identity.app import build_app
    from fusion_identity.client.identity_client import IdentityClient
    from fusion_identity.db import PgStore
    from fusion_identity.grpc import identity_pb2 as pb
    from tests.conftest import _settings

    # asyncpg pools are loop-bound: the HTTP app (TestClient portal loop) gets
    # its OWN store; the gRPC server keeps enforce_stack.store (test loop).
    http_store = PgStore(PG_URL)
    s = dataclasses.replace(_settings(), redis_url=_REDIS_URL, grpc_port=0, lease_ttl_seconds=60)
    app = build_app(s, store=http_store, run_bootstrap=False)
    with TestClient(app) as http:
        ic = IdentityClient(
            target=f"127.0.0.1:{_TEST_GRPC_PORT}",
            deadline_ms=2000,
            service_token=enforce_stack.service_token,
        )
        try:
            warm = await ic.authorize_and_acquire(enforce_stack.raw_key, "office")
            assert warm.is_allowed, pb_msg(warm)
            await ic.release_lease(warm.lease_id, _TENANT)
            r = http.put(
                f"/api/v1/admin/tenants/{_TENANT}",
                json={"max_concurrency": 1},
                headers={
                    "Authorization": f"Bearer {enforce_stack.service_token}",
                    "X-Tenant-Id": "_system",
                },
            )
            assert r.status_code == 200, r.text
            first = await ic.authorize_and_acquire(enforce_stack.raw_key, "office")
            assert first.is_allowed, pb_msg(first)
            second = await ic.authorize_and_acquire(enforce_stack.raw_key, "office")
            assert not second.is_allowed, "stale api-key cache served old concurrency"
            assert second.error_code == pb.AuthErrorCode.CONCURRENCY_LIMIT_EXCEEDED
            await ic.release_lease(first.lease_id, _TENANT)
        finally:
            await ic.close()


def pb_msg(resp) -> str:
    from fusion_identity.grpc import identity_pb2 as pb

    return pb.AuthErrorCode.Name(resp.error_code) + ": " + resp.error_message
