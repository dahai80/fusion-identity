from __future__ import annotations

import asyncio
import dataclasses
import threading

from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.kdf import _semaphore, run_kdf
from tests.conftest import _settings


def _login(client: TestClient, tenant: str = "default") -> dict:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": tenant},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_refresh_rate_limited(monkeypatch):
    # Issue #69: /refresh is throttled (per-IP) — a retry loop issuing pairs
    # every second gets 429 instead of queueing every login behind the churn.
    s = dataclasses.replace(_settings(), refresh_rate_limit=3, login_rate_window=60)
    with TestClient(build_app(s)) as c:
        codes = [
            c.post("/api/v1/auth/refresh", json={"refresh_token": "not-a-token"}).status_code
            for _ in range(6)
        ]
        assert 429 in codes
        # invalid-token requests that pass the limiter still 401
        assert 401 in codes


def test_refresh_rate_limit_disabled_at_zero():
    s = dataclasses.replace(_settings(), refresh_rate_limit=0)
    with TestClient(build_app(s)) as c:
        for _ in range(10):
            r = c.post("/api/v1/auth/refresh", json={"refresh_token": "not-a-token"})
            assert r.status_code == 401, r.text


def test_refresh_rotation_still_works(client: TestClient):
    # throttle must not break the legit single-user rotation path
    tokens = _login(client)
    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r1.status_code == 200, r1.text
    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": r1.json()["refresh_token"]})
    assert r2.status_code == 200, r2.text


def test_kdf_concurrency_capped():
    # Issue #68: run_kdf bounds concurrent off-loop KDF work — N parallel
    # calls must never exceed the semaphore cap inside the worker.
    cap_holder = {"cur": 0, "max": 0}
    lock = threading.Lock()

    def _work() -> int:
        with lock:
            cap_holder["cur"] += 1
            cap_holder["max"] = max(cap_holder["max"], cap_holder["cur"])
        # give the scheduler room to overlap workers
        import time

        time.sleep(0.05)
        with lock:
            cap_holder["cur"] -= 1
        return 1

    sem = _semaphore()
    assert sem._value >= 1  # sane cap

    async def _main() -> None:
        await asyncio.gather(*(run_kdf(_work) for _ in range(12)))

    asyncio.run(_main())
    assert cap_holder["max"] <= 4, cap_holder
    assert cap_holder["max"] > 1  # parallelism actually happened up to the cap
