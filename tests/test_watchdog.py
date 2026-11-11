from __future__ import annotations

import dataclasses
import logging
import socket
import threading

import pytest

from fusion_identity.config import load_settings
from fusion_identity.watchdog import StallWatchdog
from tests.conftest import _settings


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _accept_and_hold(sock: socket.socket, stop: threading.Event) -> None:
    # Simulated event-loop stall: TCP accepts but HTTP never answers —
    # exactly the 2026-11-10 incident signature (uvicorn accepted the
    # connection, the blocked loop never produced a response).
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = sock.accept()
        except TimeoutError:
            continue
        stop.wait(3.0)
        conn.close()


def test_watchdog_logs_critical_on_stall(caplog):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    host, port = srv.getsockname()
    stop = threading.Event()
    t = threading.Thread(target=_accept_and_hold, args=(srv, stop), daemon=True)
    t.start()
    wd = StallWatchdog(port, host=host, interval=5, timeout=1)
    try:
        with caplog.at_level(logging.CRITICAL, logger="fusion_identity.watchdog"):
            wd._probe()
        assert wd._stalled is True
        criticals = [r for r in caplog.records if r.levelno == logging.CRITICAL]
        assert criticals and "STALL" in criticals[0].getMessage()
        # repeated stalls do not spam — only the transition logs CRITICAL
        caplog.clear()
        wd._probe()
        assert not [r for r in caplog.records if r.levelno == logging.CRITICAL]
    finally:
        stop.set()
        t.join(timeout=2)
        srv.close()


def test_watchdog_recovers_after_stall(caplog):
    wd = StallWatchdog(1, host="127.0.0.1", interval=5, timeout=1)
    wd._stopped.set()  # probe directly, no timer reschedule
    wd._stalled = True

    class _OK:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    import urllib.request

    orig = urllib.request.urlopen
    urllib.request.urlopen = lambda *a, **k: _OK()  # type: ignore[assignment]
    try:
        with caplog.at_level(logging.WARNING, logger="fusion_identity.watchdog"):
            wd._probe()
    finally:
        urllib.request.urlopen = orig  # type: ignore[assignment]
    assert wd._stalled is False
    assert any("RECOVERED" in r.getMessage() for r in caplog.records)


def test_watchdog_stop_cancels_timer():
    wd = StallWatchdog(_free_port(), interval=5, timeout=1)
    wd.start()
    wd.stop()
    assert wd._stopped.is_set()
    assert wd._timer is not None
    # cancel() flags the timer finished (thread may linger up to one interval)
    assert wd._timer.finished.is_set()


def test_settings_default_watchdog_off_load_settings_on():
    # Dataclass default 0 — offline tests never probe real ports.
    assert _settings().stall_watchdog_seconds == 0
    # load_settings defaults ON (30s) for production; env opts out.
    import os

    old = {
        k: os.environ.get(k)
        for k in (
            "FUSION_IDENTITY_JWT_KEY",
            "FUSION_IDENTITY_SERVICE_TOKEN",
            "FUSION_IDENTITY_KEK",
            "FUSION_IDENTITY_STALL_WATCHDOG",
        )
    }
    os.environ["FUSION_IDENTITY_JWT_KEY"] = "k" * 32
    os.environ["FUSION_IDENTITY_SERVICE_TOKEN"] = "t" * 24
    os.environ["FUSION_IDENTITY_KEK"] = "e" * 32
    try:
        os.environ.pop("FUSION_IDENTITY_STALL_WATCHDOG", None)
        assert load_settings().stall_watchdog_seconds == 30
        os.environ["FUSION_IDENTITY_STALL_WATCHDOG"] = "0"
        assert load_settings().stall_watchdog_seconds == 0
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_app_startup_starts_watchdog(monkeypatch):
    # Startup wiring: settings.stall_watchdog_seconds > 0 → watchdog thread
    # starts on startup and stops cleanly on shutdown.
    s = dataclasses.replace(_settings(), stall_watchdog_seconds=5)
    from starlette.testclient import TestClient

    from fusion_identity.app import build_app

    with TestClient(build_app(s)) as c:
        wd = c.app.state.watchdog
        assert wd is not None
        assert wd._timer is not None and wd._timer.is_alive()
    assert wd._stopped.is_set()


@pytest.mark.parametrize("kwargs", [{"interval": 0}, {"timeout": 0}])
def test_watchdog_clamps_nonpositive(kwargs):
    wd = StallWatchdog(11470, interval=kwargs.get("interval", 30), timeout=kwargs.get("timeout", 5))
    assert wd._interval >= 5
    assert wd._timeout >= 1
