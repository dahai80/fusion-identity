from __future__ import annotations

import logging
import os
import uuid

import pytest
import redis.asyncio as aioredis

from fusion_identity.cache import IdentityCache

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("FUSION_IDENTITY_REDIS_URL", "redis://127.0.0.1:6379/0")

pytestmark = pytest.mark.integration


@pytest.fixture
async def cache():
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    await redis.ping()
    c = IdentityCache(redis)
    await c.init_scripts()
    yield c, redis
    await redis.aclose()


def _state() -> str:
    return "smoke_" + uuid.uuid4().hex[:12]


async def test_login_rate_limiter_denies_after_threshold(cache):
    c, redis = cache
    key_suffix = _state()
    tenant = "t" + key_suffix
    ip_key = c._login_key(tenant, "1.2.3.4")
    await redis.delete(ip_key)
    limit = 3
    results = [
        await c.check_login_rate(tenant, "1.2.3.4", None, limit, 60) for _ in range(limit + 2)
    ]
    assert all(results[:limit]) is True
    assert all(results[limit:]) is False


async def test_login_rate_window_expires(cache):
    c, redis = cache
    key_suffix = _state()
    tenant = "t" + key_suffix
    ip_key = c._login_key(tenant, "1.2.3.4")
    await redis.delete(ip_key)
    ok = await c.check_login_rate(tenant, "1.2.3.4", None, 5, 1)
    assert ok is True
    ttl = await redis.ttl(ip_key)
    assert 0 < ttl <= 1


async def test_login_rate_dual_bucket_user(cache):
    c, redis = cache
    key_suffix = _state()
    tenant = "t" + key_suffix
    ip_key = c._login_key(tenant, "1.2.3.4")
    user_key = c._login_user_key(tenant, "alice")
    await redis.delete(ip_key)
    await redis.delete(user_key)
    for _ in range(2):
        assert await c.check_login_rate(tenant, "1.2.3.4", "alice", 2, 60) is True
    denied = await c.check_login_rate(tenant, "1.2.3.4", "alice", 2, 60)
    assert denied is False


async def test_oidc_state_one_shot_consume(cache):
    c, redis = cache
    state = _state()
    await c.put_oidc_state(state, {"idp_id": "kc", "nonce": "N1"}, 60)
    popped = await c.pop_oidc_state(state)
    assert popped is not None and popped["idp_id"] == "kc"
    again = await c.pop_oidc_state(state)
    assert again is None


async def test_oidc_state_getdel_atomic_under_race(cache):
    c, redis = cache
    state = _state()
    await c.put_oidc_state(state, {"idp_id": "kc", "nonce": "N2"}, 60)
    import asyncio

    pops = await asyncio.gather(*[c.pop_oidc_state(state) for _ in range(8)])
    non_none = [p for p in pops if p is not None]
    assert len(non_none) == 1
    assert non_none[0]["nonce"] == "N2"


async def test_oidc_state_ttl_expiry(cache):
    c, redis = cache
    state = _state()
    await c.put_oidc_state(state, {"idp_id": "kc"}, 1)
    import asyncio

    await asyncio.sleep(1.2)
    popped = await c.pop_oidc_state(state)
    assert popped is None
