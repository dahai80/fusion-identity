from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class IdentityCache:
    def __init__(self, redis: Any) -> None:
        self._redis = redis

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
