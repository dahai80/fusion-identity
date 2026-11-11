from __future__ import annotations

import logging
import threading
import time
import urllib.request

logger = logging.getLogger(__name__)


class StallWatchdog:
    # Issue #64: loop-independent health probe. The probe runs on a
    # threading.Timer OUTSIDE the asyncio event loop, so a stalled loop
    # cannot stop the watchdog — it still times out and logs CRITICAL,
    # making the stall observable. The 2026-11-10 incident stalled for
    # minutes with zero logging (TCP accepted, HTTP never answered).
    # Detection only — recovery is the operator's fusion-sv restart.
    def __init__(self, port: int, host: str = "127.0.0.1", interval: int = 30, timeout: int = 5):
        self._url = f"http://{host}:{port}/health"
        self._interval = max(5, int(interval))
        self._timeout = max(1, int(timeout))
        self._timer: threading.Timer | None = None
        self._stopped = threading.Event()
        self._stalled = False

    def _probe(self) -> None:
        ok = False
        start = time.monotonic()
        try:
            with urllib.request.urlopen(self._url, timeout=self._timeout) as resp:
                ok = resp.status == 200
        except Exception as exc:
            logger.warning("watchdog: health probe failed: %s", exc)
        elapsed = time.monotonic() - start
        if not ok and elapsed >= self._timeout:
            if not self._stalled:
                self._stalled = True
                logger.critical(
                    "watchdog: event loop STALL detected — /health unresponsive for "
                    ">=%ds (TCP accepts but no HTTP response). Suspect a blocking sync "
                    "call in a request handler; restart via "
                    "`fusion-sv restart fusion-identity`",
                    self._timeout,
                )
        elif ok and self._stalled:
            self._stalled = False
            logger.warning("watchdog: stall RECOVERED (probe answered in %.2fs)", elapsed)
        if not self._stopped.is_set():
            t = threading.Timer(self._interval, self._probe)
            t.daemon = True
            self._timer = t
            t.start()

    def start(self) -> None:
        self._stopped.clear()
        t = threading.Timer(self._interval, self._probe)
        t.daemon = True
        self._timer = t
        t.start()
        logger.info(
            "watchdog: stall watchdog started url=%s interval=%ds timeout=%ds",
            self._url,
            self._interval,
            self._timeout,
        )

    def stop(self) -> None:
        self._stopped.set()
        if self._timer is not None:
            self._timer.cancel()
