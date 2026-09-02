from __future__ import annotations

import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)

ACQUIRE_LUA = """
local key = KEYS[1]
local lease_prefix = KEYS[2]
local max_limit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local lease_id = ARGV[3]

local current = tonumber(redis.call('get', key) or "0")
if current >= max_limit then
    return 0
end
local n = redis.call('incr', key)
if n > max_limit then
    redis.call('decr', key)
    return 0
end
redis.call('expire', key, ttl)
redis.call('set', lease_prefix .. lease_id, key, 'EX', ttl)
return 1
"""

RELEASE_LUA = """
local lease_key = KEYS[1]
local val = redis.call('get', lease_key)
if not val then
    return 0
end
redis.call('del', lease_key)
local current = tonumber(redis.call('get', val) or "0")
if current > 0 then
    redis.call('decr', val)
end
return 1
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

    def _concurrency_key(self, tenant_id: str) -> str:
        return f"concurrency:{tenant_id}"

    def _lease_prefix(self) -> str:
        return "lease:"

    def _lease_key(self, lease_id: str) -> str:
        return f"lease:{lease_id}"

    async def try_acquire(self, tenant_id: str, max_concurrency: int) -> str | None:
        if max_concurrency <= 0:
            logger.warning("concurrency: acquire denied tenant=%s max=0", tenant_id)
            return None
        lease_id = f"{tenant_id}:{uuid.uuid4().hex[:12]}"
        result = await self._lua_acquire(
            keys=[self._concurrency_key(tenant_id), self._lease_prefix()],
            args=[max_concurrency, self._lease_ttl, lease_id],
        )
        if result == 1:
            logger.debug(
                "concurrency: acquired tenant=%s lease=%s max=%s",
                tenant_id,
                lease_id,
                max_concurrency,
            )
            return lease_id
        logger.info(
            "concurrency: denied tenant=%s max=%s (limit reached)", tenant_id, max_concurrency
        )
        return None

    async def release(self, lease_id: str, reason: str = "completed") -> bool:
        result = await self._lua_release(keys=[self._lease_key(lease_id)], args=[])
        if result == 1:
            logger.debug("concurrency: released lease=%s reason=%s", lease_id, reason)
            return True
        logger.debug("concurrency: release no-op lease=%s (expired/unknown)", lease_id)
        return False

    async def active_count(self, tenant_id: str) -> int:
        val = await self._redis.get(self._concurrency_key(tenant_id))
        return int(val or 0)
