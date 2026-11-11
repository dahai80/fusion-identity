from __future__ import annotations

import asyncio
import logging
import os

logger = logging.getLogger(__name__)

# Issue #68: every argon2 operation allocates ~64MB and burns CPU for tens of
# ms. Unbounded asyncio.to_thread fan-out under a login burst (or a retry
# storm) multiplies that into memory pressure and machine-wide CPU
# starvation — the event loop itself then starves and /health stalls. A
# process-wide semaphore bounds concurrent KDF work; excess callers queue
# (bounded wait) instead of compounding the pressure. Default 4 — well above
# any legitimate sequential load, far below saturation.
_DEFAULT_KDF_CONCURRENCY = 4


def _kdf_concurrency() -> int:
    raw = os.environ.get("FUSION_IDENTITY_KDF_CONCURRENCY", "").strip()
    if not raw:
        return _DEFAULT_KDF_CONCURRENCY
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning(
            "kdf: invalid FUSION_IDENTITY_KDF_CONCURRENCY=%r, using default %d",
            raw,
            _DEFAULT_KDF_CONCURRENCY,
        )
        return _DEFAULT_KDF_CONCURRENCY


_KDF_SEMAPHORE: asyncio.Semaphore | None = None


def _semaphore() -> asyncio.Semaphore:
    global _KDF_SEMAPHORE
    if _KDF_SEMAPHORE is None:
        _KDF_SEMAPHORE = asyncio.Semaphore(_kdf_concurrency())
        logger.info("kdf: KDF concurrency cap=%d", _kdf_concurrency())
    return _KDF_SEMAPHORE


async def run_kdf(fn, *args, **kwargs):
    # Bounded off-loop KDF execution. Never blocks the event loop: the wait
    # is awaited, the work runs on a worker thread.
    async with _semaphore():
        return await asyncio.to_thread(fn, *args, **kwargs)
