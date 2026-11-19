from __future__ import annotations

import asyncio
import dataclasses
import logging
import time

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.store import InMemoryStore
from tests.conftest import _settings

logger = logging.getLogger(__name__)

PASSWORD = "S3curePass!2026x"


@pytest.fixture
def store() -> InMemoryStore:
    return InMemoryStore()


def _make_client(store: InMemoryStore, **overrides) -> TestClient:
    app = build_app(
        dataclasses.replace(_settings(), email_verification_required=False, **overrides),
        store=store,
        run_bootstrap=True,
    )
    return TestClient(app)


@pytest.fixture
def client(store: InMemoryStore) -> TestClient:
    with _make_client(store) as c:
        yield c


def _signup(client: TestClient, username: str, email: str) -> None:
    r = client.post(
        "/api/v1/auth/register",
        json={"username": username, "password": PASSWORD, "email": email},
    )
    assert r.status_code == 201, r.text


async def _arm_token(store: InMemoryStore, user_id: str, token: str, ttl: float = 1800) -> None:
    import hashlib

    ok = await store.set_password_reset_token(
        user_id, hashlib.sha256(token.encode()).hexdigest(), time.time() + ttl
    )
    assert ok


async def _user_id_by_email(store: InMemoryStore, email: str) -> str:
    user = await store.get_user_by_email(email)
    assert user is not None
    return user["user_id"]


def test_uniform_response_existing_vs_missing(client):
    # Issue #98 acceptance: reset request for a non-existent account returns
    # the exact same status + body as for an existing one.
    r_missing = client.post("/api/v1/auth/password/forgot", json={"email": "nobody@x.io"})
    assert r_missing.status_code == 200
    assert r_missing.json() == {"sent": True}
    _signup(client, "alice", "alice@x.io")
    r_existing = client.post("/api/v1/auth/password/forgot", json={"email": "alice@x.io"})
    assert r_existing.status_code == 200
    assert r_existing.json() == r_missing.json()
    logger.info("uniform response verified: existing == missing")


def test_hit_path_not_timing_oracle(client, monkeypatch):
    # Issue #98: delivery is fire-and-forget — a slow SMTP round-trip must
    # not make the existing-account response measurably slower than the
    # miss path (which does no I/O).
    async def slow_send(settings, to_email, subject, body):
        await asyncio.sleep(30)
        return "sent"

    monkeypatch.setattr("fusion_identity.routes.auth.send_password_reset_email", slow_send)
    _signup(client, "bob", "bob@x.io")
    t0 = time.monotonic()
    r = client.post("/api/v1/auth/password/forgot", json={"email": "bob@x.io"})
    elapsed = time.monotonic() - t0
    assert r.status_code == 200 and r.json() == {"sent": True}
    assert elapsed < 5, f"hit path waited on delivery: {elapsed:.1f}s"
    logger.info("hit path returned in %.2fs with 30s delivery pending", elapsed)


def test_backoff_progressive_throttle(client, caplog):
    # Issue #98 acceptance: rapid repeated requests for the same account get
    # progressively throttled (growing Retry-After), with a spike WARNING.
    _signup(client, "carol", "carol@x.io")
    with caplog.at_level(logging.INFO, logger="fusion_identity.ratelimit"):
        r1 = client.post("/api/v1/auth/password/forgot", json={"email": "carol@x.io"})
        assert r1.status_code == 200
        r2 = client.post("/api/v1/auth/password/forgot", json={"email": "carol@x.io"})
        assert r2.status_code == 200, "double-submit must stay within burst tolerance"
        r3 = client.post("/api/v1/auth/password/forgot", json={"email": "carol@x.io"})
        assert r3.status_code == 429
        ra3 = int(r3.headers["Retry-After"])
        r4 = client.post("/api/v1/auth/password/forgot", json={"email": "carol@x.io"})
        assert r4.status_code == 429
        ra4 = int(r4.headers["Retry-After"])
    assert ra3 >= 8, ra3
    assert ra4 > ra3, (ra3, ra4)
    assert any("spike" in rec.getMessage() for rec in caplog.records)
    logger.info("progressive backoff verified: retry_after %d -> %d", ra3, ra4)


def test_backoff_uniform_for_missing_account(client):
    # Throttling keys on the REQUESTED email — identical for accounts that
    # do not exist (no enumeration via the abuse gate either).
    r1 = client.post("/api/v1/auth/password/forgot", json={"email": "ghost@x.io"})
    assert r1.status_code == 200
    r2 = client.post("/api/v1/auth/password/forgot", json={"email": "ghost@x.io"})
    assert r2.status_code == 200
    r3 = client.post("/api/v1/auth/password/forgot", json={"email": "ghost@x.io"})
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
    logger.info("backoff uniform for missing account verified")


def test_backoff_per_account_across_ips(client, monkeypatch):
    # Issue #98: mail-bombing gate — rotating IPs cannot re-arm the same
    # target address; the per-account (email) key still throttles.
    import fusion_identity.routes.auth as auth_routes

    ips = iter(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
    monkeypatch.setattr(auth_routes, "client_ip", lambda request: next(ips))
    _signup(client, "dave", "dave@x.io")
    r1 = client.post("/api/v1/auth/password/forgot", json={"email": "dave@x.io"})
    assert r1.status_code == 200
    r2 = client.post("/api/v1/auth/password/forgot", json={"email": "dave@x.io"})
    assert r2.status_code == 200
    r3 = client.post("/api/v1/auth/password/forgot", json={"email": "dave@x.io"})
    assert r3.status_code == 429, "email key must throttle across IPs"
    logger.info("per-account backoff across rotating IPs verified")


def test_backoff_disabled_when_base_zero(store):
    # base=0 disables the backoff plane entirely (operator opt-out).
    with _make_client(store, reset_backoff_base_seconds=0) as client:
        for _ in range(4):
            r = client.post("/api/v1/auth/password/forgot", json={"email": "any@x.io"})
            assert r.status_code == 200
    logger.info("backoff opt-out verified")


def test_token_single_use_and_expiry(store, client):
    # Issue #98: used token rejected on second use; expired token rejected.
    _signup(client, "erin", "erin@x.io")
    uid = asyncio.run(_user_id_by_email(store, "erin@x.io"))
    asyncio.run(_arm_token(store, uid, "tok-live-abcdef123456"))
    r1 = client.post(
        "/api/v1/auth/password/reset",
        json={"token": "tok-live-abcdef123456", "new_password": "N3wPassword!2026"},
    )
    assert r1.status_code == 200, r1.text
    r2 = client.post(
        "/api/v1/auth/password/reset",
        json={"token": "tok-live-abcdef123456", "new_password": "N3wPassword!2027"},
    )
    assert r2.status_code == 400
    asyncio.run(_arm_token(store, uid, "tok-old-abcdef123456", ttl=-1))
    r3 = client.post(
        "/api/v1/auth/password/reset",
        json={"token": "tok-old-abcdef123456", "new_password": "N3wPassword!2028"},
    )
    assert r3.status_code == 400
    logger.info("single-use + expiry rejection verified")


def test_change_password_invalidates_outstanding_token(store, client):
    # Issue #98: a password change via the account path must kill any
    # reset token armed before the rotation.
    _signup(client, "frank", "frank@x.io")
    uid = asyncio.run(_user_id_by_email(store, "frank@x.io"))
    asyncio.run(_arm_token(store, uid, "tok-pending-abcdef123456"))
    login = client.post("/api/v1/auth/login", json={"username": "frank", "password": PASSWORD})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    change = client.post(
        "/api/v1/auth/password",
        json={"old_password": PASSWORD, "new_password": "R0tated!Pass01"},
        headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": "community"},
    )
    assert change.status_code == 200, change.text
    r = client.post(
        "/api/v1/auth/password/reset",
        json={"token": "tok-pending-abcdef123456", "new_password": "StolenPassword!99"},
    )
    assert r.status_code == 400, "pre-rotation reset token must be dead"
    logger.info("password change invalidates outstanding reset token verified")
