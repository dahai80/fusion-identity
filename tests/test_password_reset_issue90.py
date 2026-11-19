from __future__ import annotations

import dataclasses
import logging

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


@pytest.fixture
def client(store: InMemoryStore) -> TestClient:
    app = build_app(
        dataclasses.replace(_settings(), email_verification_required=False),
        store=store,
        run_bootstrap=True,
    )
    with TestClient(app) as c:
        yield c


def _signup(client: TestClient, username: str, email: str) -> None:
    r = client.post(
        "/api/v1/auth/register",
        json={"username": username, "password": PASSWORD, "email": email},
    )
    assert r.status_code == 201, r.text


def _capture_reset_email(client: TestClient, monkeypatch, email: str) -> str:
    # Issue #98: delivery is now fire-and-forget — the response returns
    # before the task runs, so wait on an event instead of reading the
    # capture right after the POST.
    import threading

    captured: dict[str, str] = {}
    delivered = threading.Event()

    async def fake_send(settings, to_email, subject, body):
        captured["body"] = body
        delivered.set()
        return "sent"

    monkeypatch.setattr("fusion_identity.email_sender.send_email", fake_send)
    r = client.post("/api/v1/auth/password/reset-request", json={"email": email})
    assert r.status_code == 200
    assert delivered.wait(timeout=10), "async reset email never delivered"
    for ln in captured.get("body", "").splitlines():
        if "/auth/?reset=" in ln:
            return ln.split("reset=")[1].strip()
    raise AssertionError("reset link not rendered in email body")


def test_reset_request_alias_matches_forgot(store, monkeypatch):
    # Issue #90: /password/reset-request is a first-class alias of
    # /password/forgot — same uniform response, same token plane. Own client
    # with the backoff plane off: this test exercises alias identity, not
    # the issue #98 abuse gate (3 rapid requests would legitimately 429).
    import dataclasses as _dc

    from fusion_identity.app import build_app as _build

    app = _build(
        _dc.replace(_settings(), email_verification_required=False, reset_backoff_base_seconds=0),
        store=store,
        run_bootstrap=True,
    )
    with TestClient(app) as client:
        _signup(client, "alice", "alice@example.com")
        r_forgot = client.post("/api/v1/auth/password/forgot", json={"email": "ghost@example.com"})
        r_alias = client.post(
            "/api/v1/auth/password/reset-request", json={"email": "ghost@example.com"}
        )
        assert r_forgot.status_code == r_alias.status_code == 200
        assert r_forgot.json() == r_alias.json() == {"sent": True}

        # The alias-armed token actually resets the password.
        token = _capture_reset_email(client, monkeypatch, "alice@example.com")
        r = client.post(
            "/api/v1/auth/password/reset",
            json={"token": token, "new_password": "N3wPassword!2026"},
        )
        assert r.status_code == 200, r.text
        r = client.post(
            "/api/v1/auth/login", json={"username": "alice", "password": "N3wPassword!2026"}
        )
        assert r.status_code == 200
        logger.info("reset-request alias verified")


def test_reset_ttl_default_30min():
    # Issue #90: reset TTL must default to <= 30 minutes.
    from dataclasses import fields

    from fusion_identity.config import Settings

    ttl = next(f for f in fields(Settings) if f.name == "password_reset_ttl_seconds")
    assert ttl.default == 1800


def test_reset_success_notification_sent(client, monkeypatch):
    # Issue #90: after a successful reset the user gets a confirmation email.
    _signup(client, "bob", "bob@example.com")
    token = _capture_reset_email(client, monkeypatch, "bob@example.com")

    sent: dict[str, str] = {}

    async def fake_notify(settings, to_email, username):
        sent["to"] = to_email
        sent["username"] = username
        return "sent"

    monkeypatch.setattr(
        "fusion_identity.routes.auth.send_password_reset_success_email", fake_notify
    )
    r = client.post(
        "/api/v1/auth/password/reset",
        json={"token": token, "new_password": "N3wPassword!2026"},
    )
    assert r.status_code == 200
    assert sent["to"] == "bob@example.com"
    assert sent["username"] == "bob"
    logger.info("reset success notification verified")


def test_reset_request_audited(client, store, monkeypatch):
    # Issue #90: the request step lands on the audit trail (not only the reset).
    _signup(client, "carol", "carol@example.com")
    _capture_reset_email(client, monkeypatch, "carol@example.com")
    actions = [row["action"] for row in store._audit]
    assert "auth.password_reset_requested" in actions


def test_reset_request_unknown_email_no_audit_row(client, store):
    # Enum-free: a miss must not leave an audit row that reveals an account.
    before = len(store._audit)
    r = client.post("/api/v1/auth/password/reset-request", json={"email": "ghost@example.com"})
    assert r.status_code == 200
    assert r.json() == {"sent": True}
    after = [row["action"] for row in store._audit[before:]]
    assert "auth.password_reset_requested" not in after
