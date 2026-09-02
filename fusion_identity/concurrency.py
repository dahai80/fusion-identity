from __future__ import annotations

import logging
import time
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# Sorted-set is the authority for active leases; counter derived from ZCARD.
# ACQUIRE cleans expired members first (reaper built into hot path — F2 fix),
# returns post-op live count (P4 fix — saves a separate active_count GET).
ACQUIRE_LUA = """
local ckey = KEYS[1]
local lset = KEYS[2]
local lkey_prefix = KEYS[3]
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local lease_id = ARGV[3]
local max_limit = tonumber(ARGV[4])

local expired = redis.call('zrangebyscore', lset, 0, now)
for _, eid in ipairs(expired) do
    redis.call('del', lkey_prefix .. eid)
end
redis.call('zremrangebyscore', lset, 0, now)

local current = redis.call('zcard', lset)
if current >= max_limit then
    return 0
end
redis.call('zadd', lset, now + ttl, lease_id)
redis.call('set', lkey_prefix .. lease_id, '1', 'EX', ttl)
redis.call('expire', lset, ttl + 60)
return redis.call('zcard', lset)
"""

# Returns -1 if lease not found (expired/unknown/wrong tenant), else post-op
# live count. Tenant scope enforced by the per-tenant lset key (L5 fix).
RELEASE_LUA = """
local lset = KEYS[1]
local lkey_prefix = KEYS[2]
local lease_id = ARGV[1]
if redis.call('zrem', lset, lease_id) == 0 then
    return -1
end
redis.call('del', lkey_prefix .. lease_id)
return redis.call('zcard', lset)
"""


class ConcurrencyManager:
    def __init__(self, redis: Any, lease_ttl: int = 120) -> None:
        self._redis = redis
        self._lease_ttl = lease_ttl
        self._lua_acquire = None
        self._lua_release = None

    async def init_scripts(self) -> None:
        self._lua_acquire = self._redis.register_script(ACQUIRE_LUA)
        self._lua_release = self._redis.register_script(RELEASE_LUA)
        logger.info("concurrency: lua scripts registered ttl=%ss", self._lease_ttl)

    def _leases_key(self, tenant_id: str) -> str:
        return f"leases:{tenant_id}"

    def _lease_prefix(self) -> str:
        return "lease:"

    def _lease_key(self, lease_id: str) -> str:
        return f"lease:{lease_id}"

    async def try_acquire(self, tenant_id: str, max_concurrency: int) -> tuple[str, int] | None:
        if max_concurrency <= 0:
            logger.warning("concurrency: acquire denied tenant=%s max=0", tenant_id)
            return None
        lease_id = f"{tenant_id}:{uuid.uuid4().hex[:12]}"
        now = int(time.time())
        result = await self._lua_acquire(
            keys=[self._leases_key(tenant_id), self._leases_key(tenant_id), self._lease_prefix()],
            args=[now, self._lease_ttl, lease_id, max_concurrency],
        )
        if not result or result == 0:
            logger.info(
                "concurrency: denied tenant=%s max=%s (limit reached)", tenant_id, max_concurrency
            )
            return None
        logger.debug(
            "concurrency: acquired tenant=%s lease=%s max=%s active=%s",
            tenant_id,
            lease_id,
            max_concurrency,
            result,
        )
        return lease_id, int(result)

    async def release(self, tenant_id: str, lease_id: str, reason: str = "completed") -> int:
        result = await self._lua_release(
            keys=[self._leases_key(tenant_id), self._lease_prefix()],
            args=[lease_id],
        )
        if result is None or result < 0:
            logger.debug(
                "concurrency: release no-op lease=%s tenant=%s (expired/unknown)",
                lease_id,
                tenant_id,
            )
            return -1
        logger.debug(
            "concurrency: released lease=%s tenant=%s reason=%s active=%s",
            lease_id,
            tenant_id,
            reason,
            result,
        )
        return int(result)

    async def active_count(self, tenant_id: str) -> int:
        now = int(time.time())
        lset = self._leases_key(tenant_id)
        await self._redis.zremrangebyscore(lset, 0, now)
        val = await self._redis.zcard(lset)
        return int(val or 0)
