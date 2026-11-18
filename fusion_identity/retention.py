from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class RetentionWorker:
    # Issue #91: background retention sweep. Every tick:
    #   1. purge accounts whose deletion grace window has expired
    #      (one transaction per account in PgStore);
    #   2. prune expired/revoked token ledgers;
    #   3. prune audit_log entries older than the retention window.
    # All three are idempotent, so a crashed or skipped tick self-heals.

    def __init__(
        self,
        store: Any,
        *,
        audit_retention_months: int = 12,
        tick_seconds: float = 3600.0,
    ) -> None:
        self._store = store
        self._audit_retention_months = max(1, audit_retention_months)
        self._tick_seconds = tick_seconds
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def sweep_once(self) -> dict[str, int]:
        now = time.time()
        purged = 0
        for user_id in await self._store.due_account_deletions(now):
            try:
                await self._store.purge_account(user_id)
                await self._store.append_audit(
                    tenant_id="_system",
                    user_id=None,
                    jti=None,
                    role="deleted",
                    action="account.purged",
                    resource=None,
                    detail={"user_id": user_id},
                )
                purged += 1
            except Exception:
                logger.exception("retention: purge failed user=%s", user_id)
        pruned_tokens = await self._store.prune_expired_tokens(now)
        cutoff = now - self._audit_retention_months * 30 * 24 * 3600
        pruned_audit = await self._store.prune_audit(cutoff)
        stats = {"purged": purged, "pruned_tokens": pruned_tokens, "pruned_audit": pruned_audit}
        if any(stats.values()):
            logger.info("retention sweep: %s", stats)
        return stats

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._tick_seconds)
                break
            except TimeoutError:
                pass
            try:
                await self.sweep_once()
            except Exception:
                logger.exception("retention: sweep tick failed")

    def start(self) -> None:
        self._stop.clear()
        self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except (TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None
