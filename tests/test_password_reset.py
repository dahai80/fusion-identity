from __future__ import annotations

import dataclasses
import logging
import time

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.email_sender import EmailDeliveryError
from fusion_identity.store import InMemoryStore
from tests.conftest import _settings

logger = logging.getLogger(__name__)

PASSWORD = "S3curePass!2026x"


@pytest.fixture
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture
def client(store: InMemoryStore) -> TestClient:
    # Email verification off so the signup returns a token pair directly —
    # the reset flow itself is what is under test.
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


def _forgot(client: TestClient, email: str, monkeypatch=None) -> str | None:
    captured: dict[str, str] = {}

    async def fake_send(settings, to_email, subject, body):
        captured["body"] = body
        captured["subject"] = subject
        return "sent"

    if monkeypatch is not None:
        monkeypatch.setattr("fusion_identity.email_sender.send_email", fake_send)
    r = client.post("/api/v1/auth/password/forgot", json={"email": email})
    assert r.status_code == 200
    assert r.json() == {"sent": True}
    if monkeypatch is None:
        return None
    body = captured.get("body", "")
    for ln in body.splitlines():
        if "/auth/?reset=" in ln:
            return ln.split("reset=")[1].strip()
    return None


def test_forgot_unknown_email_uniform(client):
    # Uniform response — no account enumeration.
    r = client.post("/api/v1/auth/password/forgot", json={"email": "ghost@example.com"})
    assert r.status_code == 200
    assert r.json() == {"sent": True}


def test_forgot_unknown_email_explicit_404_in_reveal_mode(client):
    # Issue #58: reveal mode returns an explicit 404 instead of fake sent.
    client.app.state.settings = dataclasses.replace(
        client.app.state.settings, password_forgot_reveal_missing=True
    )
    r = client.post("/api/v1/auth/password/forgot", json={"email": "ghost@example.com"})
    assert r.status_code == 404
    assert r.json()["detail"] == "no account for this email"


def test_forgot_delivery_failure_502_in_reveal_mode(client, monkeypatch):
    # Issue #58: in reveal mode a failed send must not claim sent.
    client.app.state.settings = dataclasses.replace(
        client.app.state.settings, password_forgot_reveal_missing=True
    )

    async def failing_send(settings, to_email, subject, body):
        raise EmailDeliveryError("smtp unavailable")

    monkeypatch.setattr("fusion_identity.email_sender.send_email", failing_send)
    _signup(client, "reveal_df", "reveal-df@example.com")
    r = client.post("/api/v1/auth/password/forgot", json={"email": "reveal-df@example.com"})
    assert r.status_code == 502
    assert r.json()["detail"] == "mail delivery failed; retry shortly"
    logger.info("uniform forgot response verified")


def test_reset_flow_changes_password(client, monkeypatch):
    _signup(client, "alice", "alice@example.com")
    token = _forgot(client, "alice@example.com", monkeypatch)
    assert token, "reset link not rendered in email body"

    r = client.post(
        "/api/v1/auth/password/reset",
        json={"token": token, "new_password": "N3wPassword!2026"},
    )
    assert r.status_code == 200
    assert r.json() == {"reset": True}

    # New password logs in; old one does not.
    r = client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": "N3wPassword!2026"}
    )
    assert r.status_code == 200
    r = client.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 401
    logger.info("reset flow verified end-to-end")


def test_reset_token_single_use(client, monkeypatch):
    _signup(client, "bob", "bob@example.com")
    token = _forgot(client, "bob@example.com", monkeypatch)
    r = client.post(
        "/api/v1/auth/password/reset", json={"token": token, "new_password": "N3wPassword!2026"}
    )
    assert r.status_code == 200
    # Replay of the same token is rejected.
    r = client.post(
        "/api/v1/auth/password/reset", json={"token": token, "new_password": "4thPassword!2026"}
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid or expired reset token"


def test_reset_rejects_unknown_token(client):
    r = client.post(
        "/api/v1/auth/password/reset",
        json={"token": "x" * 32, "new_password": "N3wPassword!2026"},
    )
    assert r.status_code == 400


def test_reset_rejects_expired_token(client, store, monkeypatch):
    _signup(client, "carol", "carol@example.com")
    token = _forgot(client, "carol@example.com", monkeypatch)
    # Rewind the armed expiry into the past.
    for u in store._users.values():
        if u.get("password_reset_expires") is not None:
            u["password_reset_expires"] = time.time() - 10
    r = client.post(
        "/api/v1/auth/password/reset", json={"token": token, "new_password": "N3wPassword!2026"}
    )
    assert r.status_code == 400


def test_reset_rejects_weak_password(client, monkeypatch):
    _signup(client, "dave", "dave@example.com")
    token = _forgot(client, "dave@example.com", monkeypatch)
    r = client.post("/api/v1/auth/password/reset", json={"token": token, "new_password": "short1"})
    assert r.status_code == 422


def test_new_forgot_invalidates_old_token(client, monkeypatch):
    _signup(client, "erin", "erin@example.com")
    t1 = _forgot(client, "erin@example.com", monkeypatch)
    t2 = _forgot(client, "erin@example.com", monkeypatch)
    assert t1 != t2
    r = client.post(
        "/api/v1/auth/password/reset", json={"token": t1, "new_password": "N3wPassword!2026"}
    )
    assert r.status_code == 400
    r = client.post(
        "/api/v1/auth/password/reset", json={"token": t2, "new_password": "N3wPassword!2026"}
    )
    assert r.status_code == 200


def test_reset_link_absolute_with_base_url(client, monkeypatch):
    s = dataclasses.replace(client.app.state.settings, public_base_url="https://fusion.example")
    client.app.state.settings = s
    captured: dict[str, str] = {}

    async def fake_send(settings, to_email, subject, body):
        captured["body"] = body
        return "sent"

    monkeypatch.setattr("fusion_identity.email_sender.send_email", fake_send)
    client.post("/api/v1/auth/password/forgot", json={"email": "nobody@example.com"})
    # No account — nothing sent.
    assert "body" not in captured
    _signup(client, "frank", "frank@example.com")
    client.post("/api/v1/auth/password/forgot", json={"email": "frank@example.com"})
    # Gateway auth portal SPA contract (#549): the reset pane is prefilled by
    # /auth/?reset=<token> — /auth/reset is not a served route.
    assert "https://fusion.example/auth/?reset=" in captured["body"]
