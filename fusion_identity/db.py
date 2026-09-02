from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    import asyncpg
except ImportError:
    asyncpg = None

_SCHEMA_FILE = "deploy/sql/schema.sql"


class StoreError(RuntimeError):
    pass


class PgStore:
    def __init__(self, database_url: str) -> None:
        if asyncpg is None:
            raise StoreError("asyncpg not installed; cannot use PgStore")
        self._database_url = database_url
        self._pool: Any = None

    async def connect(self) -> None:
        logger.info("pgstore: connecting to %s", _safe_url(self._database_url))
        self._pool = await asyncpg.create_pool(dsn=self._database_url, min_size=1, max_size=8)
        logger.info("pgstore: pool ready")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.info("pgstore: pool closed")

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *args)
            return dict(row) if row is not None else None

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *args)
            return [dict(r) for r in rows]

    async def fetchval(self, sql: str, *args: Any) -> Any:
        async with self._pool.acquire() as conn:
            return await conn.fetchval(sql, *args)

    async def execute(self, sql: str, *args: Any) -> str:
        async with self._pool.acquire() as conn:
            return await conn.execute(sql, *args)

    async def ensure_schema(self) -> None:
        logger.warning(
            "pgstore.ensure_schema: DDL file %s must be applied by operator/CI; "
            "skipping in-process DDL (Appendix A.1)",
            _SCHEMA_FILE,
        )


def _safe_url(url: str) -> str:
    if "@" in url:
        scheme, rest = url.split("://", 1)
        host = rest.split("@", 1)[1]
        return f"{scheme}://***@{host}"
    return url
