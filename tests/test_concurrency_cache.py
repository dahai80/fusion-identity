from __future__ import annotations

import asyncio
import time

import fakeredis.aioredis
import pytest

from fusion_identity.cache import IdentityCache
from fusion_identity.concurrency import ConcurrencyManager


@pytest.fixture
def redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


async def test_cache_api_key_roundtrip(redis):
    cache = IdentityCache(redis)
    await cache.init_scripts()
    info = {"tenant_id": "acme", "is_active": True, "max_concurrency": 3}
    await cache.set_api_key("fmu_xyz", info, ttl=60)
    got = await cache.get_tenant_by_api_key("fmu_xyz")
    assert got == info
    miss = await cache.get_tenant_by_api_key("fmu_nope")
    assert miss is None


async def test_cache_invalidate_tenant(redis):
    cache = IdentityCache(redis)
    await cache.init_scripts()
    await cache.set_tenant("acme", {"tenant_id": "acme"}, ttl=60)
    assert await cache.get_tenant("acme") is not None
    await cache.invalidate_tenant("acme")
    assert await cache.get_tenant("acme") is None


async def test_cache_daily_quota(redis):
    cache = IdentityCache(redis)
    await cache.init_scripts()
    ok, remaining = await cache.check_daily_quota("acme", 100)
    assert ok and remaining == 100
    total = await cache.record_token_usage("acme", 30)
    assert total == 30
    ok2, remaining2 = await cache.check_daily_quota("acme", 100)
    assert ok2 and remaining2 == 70
    await cache.record_token_usage("acme", 80)
    ok3, remaining3 = await cache.check_daily_quota("acme", 100)
    assert not ok3 and remaining3 == 0


async def test_cache_invalidate_tenant_api_keys(redis):
    cache = IdentityCache(redis)
    await cache.init_scripts()
    await cache.set_api_key("fmu_a", {"tenant_id": "acme"}, ttl=60)
    await cache.invalidate_tenant_api_keys("acme", [cache._api_key_hash("fmu_a")])
    assert await cache.get_tenant_by_api_key("fmu_a") is None


async def test_concurrency_acquire_release(redis):
    mgr = ConcurrencyManager(redis, lease_ttl=120)
    await mgr.init_scripts()
    lease1 = await mgr.try_acquire("acme", 2)
    assert lease1 is not None
    lease2 = await mgr.try_acquire("acme", 2)
    assert lease2 is not None
    lease3 = await mgr.try_acquire("acme", 2)
    assert lease3 is None
    assert await mgr.active_count("acme") == 2
    released = await mgr.release("acme", lease1[0])
    assert released >= 0
    assert await mgr.active_count("acme") == 1
    lease4 = await mgr.try_acquire("acme", 2)
    assert lease4 is not None


async def test_concurrency_release_expired_noop(redis):
    mgr = ConcurrencyManager(redis, lease_ttl=120)
    await mgr.init_scripts()
    result = await mgr.release("acme", "acme:nonexistent")
    assert result == -1


async def test_concurrency_concurrent_acquire_no_overadmit(redis):
    mgr = ConcurrencyManager(redis, lease_ttl=120)
    await mgr.init_scripts()

    results = await asyncio.gather(*[mgr.try_acquire("acme", 3) for _ in range(10)])
    acquired = [r for r in results if r is not None]
    assert len(acquired) == 3
    assert await mgr.active_count("acme") == 3


async def test_concurrency_lease_ttl_reaper(redis):
    # T1: expired leases must free the concurrency slot (F2 fix).
    mgr = ConcurrencyManager(redis, lease_ttl=1)
    await mgr.init_scripts()
    acquired = await mgr.try_acquire("acme", 1)
    assert acquired is not None
    assert await mgr.active_count("acme") == 1
    time.sleep(1.5)
    # New acquire must succeed because the expired lease is reaped on the hot path.
    acquired2 = await mgr.try_acquire("acme", 1)
    assert acquired2 is not None
    assert await mgr.active_count("acme") == 1


async def test_rpm_sliding_window(redis):
    cache = IdentityCache(redis)
    await cache.init_scripts()
    for _ in range(3):
        ok, _ = await cache.check_rpm("acme", 3)
        assert ok
    ok4, remaining = await cache.check_rpm("acme", 3)
    assert ok4 is False
    assert remaining == 0
