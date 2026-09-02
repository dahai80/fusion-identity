from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# Atomic check-and-reserve: increment then rollback if over cap (L2 fix).
RESERVE_QUOTA_LUA = """
local key = KEYS[1]
local add = tonumber(ARGV[1])
local cap = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local cur = tonumber(redis.call('get', key) or "0")
if cur + add > cap then
    return {0, math.max(0, cap - cur)}
end
local n = redis.call('incrby', key, add)
redis.call('expire', key, ttl)
return {1, math.max(0, cap - n)}
"""

# Sliding-window RPM via sorted set (L1 fix). Only the first member in a fresh
# window sets expiry; window closes correctly under sustained traffic.
CHECK_RPM_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('zremrangebyscore', key, 0, now - 60)
local count = redis.call('zcard', key)
if count >= limit then
    return {0, math.max(0, limit - count)}
end
redis.call('zadd', key, now, now .. ":" .. ARGV[3])
if count == 0 then
    redis.call('expire', key, 70)
end
return {1, math.max(0, limit - count - 1)}
"""


class IdentityCache:
    def __init__(self, redis: Any) -> None:
        self._redis = redis
        self._lua_reserve = None
        self._lua_rpm = None

    async def init_scripts(self) -> None:
        self._lua_reserve = self._redis.register_script(RESERVE_QUOTA_LUA)
        self._lua_rpm = self._redis.register_script(CHECK_RPM_LUA)
        logger.info("cache: lua scripts registered (reserve_quota, rpm)")

    def _api_key_hash(self, api_key: str) -> str:
        return hashlib.sha256(api_key.encode()).hexdigest()

    def _api_key_key(self, api_key: str) -> str:
        return f"apikey:{self._api_key_hash(api_key)}"

    def _tenant_key(self, tenant_id: str) -> str:
        return f"tenant:{tenant_id}"

    def _quota_key(self, tenant_id: str, day: str | None = None) -> str:
        day = day or time.strftime("%Y-%m-%d")
        return f"quota:{tenant_id}:{day}"

    async def get_tenant_by_api_key(self, api_key: str) -> dict[str, Any] | None:
        raw = await self._redis.get(self._api_key_key(api_key))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logger.warning("cache: corrupt apikey entry, dropping")
            await self._redis.delete(self._api_key_key(api_key))
            return None

    async def set_api_key(self, api_key: str, tenant_info: dict[str, Any], ttl: int = 300) -> None:
        await self._redis.set(
            self._api_key_key(api_key), json.dumps(tenant_info, default=str), ex=ttl
        )
        logger.debug("cache: set apikey tenant=%s ttl=%ss", tenant_info.get("tenant_id"), ttl)

    async def invalidate_api_key(self, api_key: str) -> None:
        await self._redis.delete(self._api_key_key(api_key))

    async def invalidate_api_key_by_hash(self, key_hash: str) -> None:
        await self._redis.delete(f"apikey:{key_hash}")
        logger.info("cache: invalidated apikey hash=%s", key_hash[:12])

    async def invalidate_tenant_api_keys(self, tenant_id: str, api_key_hashes: list[str]) -> None:
        # Quota-update invalidation hook (L4 fix): strip stale apikey cache so
        # the old lenient quota does not authorize for up to 300s.
        if not api_key_hashes:
            return
        pipe = self._redis.pipeline()
        for h in api_key_hashes:
            pipe.delete(f"apikey:{h}")
        await pipe.execute()
        logger.info(
            "cache: invalidated %s apikey entries for tenant=%s (quota change)",
            len(api_key_hashes),
            tenant_id,
        )

    async def get_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        raw = await self._redis.get(self._tenant_key(tenant_id))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            await self._redis.delete(self._tenant_key(tenant_id))
            return None

    async def set_tenant(self, tenant_id: str, info: dict[str, Any], ttl: int = 300) -> None:
        await self._redis.set(self._tenant_key(tenant_id), json.dumps(info, default=str), ex=ttl)

    async def invalidate_tenant(self, tenant_id: str) -> None:
        await self._redis.delete(self._tenant_key(tenant_id))
        logger.info("cache: invalidated tenant=%s", tenant_id)

    async def check_daily_quota(self, tenant_id: str, daily_limit: int) -> tuple[bool, int]:
        used = int(await self._redis.get(self._quota_key(tenant_id)) or 0)
        return used < daily_limit, max(0, daily_limit - used)

    async def reserve_daily_quota(self, tenant_id: str, daily_limit: int) -> tuple[bool, int]:
        # NOTE: reserves a token placeholder of 0 here — actual token usage is
        # recorded by record_token_usage after a successful response. The
        # reserve is the gate; the counter is the authority used by
        # remaining_quota. Redis counter is the hot-path authority, Pg ledger
        # is reconciled separately (L9 — no cross-store tx; operator runs
        # periodic reconciliation).
        if self._lua_reserve is None:
            await self.init_scripts()
        result = await self._lua_reserve(
            keys=[self._quota_key(tenant_id)],
            args=[0, daily_limit, 86400 * 7],
        )
        ok = bool(int(result[0]))
        remaining = int(result[1])
        return ok, remaining

    async def refund_daily_quota(self, tenant_id: str, tokens: int) -> None:
        if tokens > 0:
            await self._redis.decrby(self._quota_key(tenant_id), tokens)

    async def record_token_usage(self, tenant_id: str, tokens: int) -> int:
        key = self._quota_key(tenant_id)
        pipe = self._redis.pipeline()
        pipe.incrby(key, tokens)
        pipe.expire(key, 86400 * 7)
        results = await pipe.execute()
        new_total = int(results[0] or 0)
        logger.debug("cache: token usage tenant=%s +%s total=%s", tenant_id, tokens, new_total)
        return new_total

    async def remaining_quota(self, tenant_id: str, daily_limit: int) -> int:
        used = int(await self._redis.get(self._quota_key(tenant_id)) or 0)
        return max(0, daily_limit - used)

    def _rpm_key(self, tenant_id: str) -> str:
        return f"rpm:{tenant_id}"

    async def check_rpm(self, tenant_id: str, rpm_limit: int) -> tuple[bool, int]:
        if rpm_limit <= 0:
            return True, rpm_limit
        if self._lua_rpm is None:
            await self.init_scripts()
        now = int(time.time())
        uid = time.time_ns()
        result = await self._lua_rpm(
            keys=[self._rpm_key(tenant_id)],
            args=[now, rpm_limit, uid],
        )
        ok = bool(int(result[0]))
        remaining = int(result[1])
        logger.debug(
            "cache: rpm check tenant=%s limit=%s ok=%s remaining=%s",
            tenant_id,
            rpm_limit,
            ok,
            remaining,
        )
        return ok, remaining

    async def reset_rpm(self, tenant_id: str) -> None:
        await self._redis.delete(self._rpm_key(tenant_id))
        logger.debug("cache: reset rpm tenant=%s", tenant_id)
