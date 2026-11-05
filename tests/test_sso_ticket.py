from __future__ import annotations

import dataclasses
import logging

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from tests.conftest import TEST_SERVICE_TOKEN, _settings

logger = logging.getLogger(__name__)

_SVC = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"}


@pytest.fixture
def tc(monkeypatch):
    s = dataclasses.replace(_settings(), email_verification_required=False)
    with TestClient(build_app(s)) as c:
        yield c


def _register(c, username):
    r = c.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "Password123", "email": f"{username}@x.io"},
    )
    assert r.status_code == 201, r.text
    return r.json()["user_id"]


def _login(c, username, password, tid):
    r = c.post(
        "/api/v1/auth/login", json={"username": username, "password": password, "tenant_id": tid}
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_ticket_issue_and_exchange_roundtrip(tc):
    _register(tc, "ssousr1")
    tok = _login(tc, "ssousr1", "Password123", "community")
    r = tc.post(
        "/api/v1/auth/ticket",
        headers={"Authorization": f"Bearer {tok}", "X-Tenant-Id": "community"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ticket"].startswith("fsso_")
    assert body["expires_in"] == 60
    # the raw ticket never lands in the audit trail
    assert all("fsso_" not in str(a) for a in str(tc.app.state.store._audit))
    ex = tc.post("/api/v1/auth/ticket/exchange", json={"ticket": body["ticket"]})
    assert ex.status_code == 200, ex.text
    pair = ex.json()
    assert pair["access_token"] and pair["refresh_token"]
    v = tc.post("/api/v1/auth/verify", json={"token": pair["access_token"]}, headers=_SVC)
    assert v.status_code == 200, v.text
    assert v.json()["tid"] == "community"
    logger.info("sso roundtrip ok user=ssousr1")


def test_ticket_replay_rejected(tc):
    _register(tc, "ssousr2")
    tok = _login(tc, "ssousr2", "Password123", "community")
    r = tc.post(
        "/api/v1/auth/ticket",
        headers={"Authorization": f"Bearer {tok}", "X-Tenant-Id": "community"},
    )
    ticket = r.json()["ticket"]
    first = tc.post("/api/v1/auth/ticket/exchange", json={"ticket": ticket})
    assert first.status_code == 200, first.text
    replay = tc.post("/api/v1/auth/ticket/exchange", json={"ticket": ticket})
    assert replay.status_code == 401
    assert replay.json()["detail"] == "invalid ticket"


def test_ticket_expired_rejected(tc):
    _register(tc, "ssousr3")
    tok = _login(tc, "ssousr3", "Password123", "community")
    r = tc.post(
        "/api/v1/auth/ticket",
        headers={"Authorization": f"Bearer {tok}", "X-Tenant-Id": "community"},
    )
    ticket = r.json()["ticket"]
    h = __import__("hashlib").sha256(ticket.encode()).hexdigest()
    tc.app.state.store._sso_tickets[h]["expires_at"] = 0
    ex = tc.post("/api/v1/auth/ticket/exchange", json={"ticket": ticket})
    assert ex.status_code == 401


def test_ticket_unknown_rejected(tc):
    r = tc.post("/api/v1/auth/ticket/exchange", json={"ticket": "fsso_" + "x" * 40})
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid ticket"


def test_ticket_issue_requires_bearer(tc):
    r = tc.post("/api/v1/auth/ticket")
    assert r.status_code in (401, 403)


def test_ticket_exchange_membership_revoked(tc):
    uid = _register(tc, "ssousr4")
    tok = _login(tc, "ssousr4", "Password123", "community")
    r = tc.post(
        "/api/v1/auth/ticket",
        headers={"Authorization": f"Bearer {tok}", "X-Tenant-Id": "community"},
    )
    ticket = r.json()["ticket"]
    # membership revoked between issue and exchange — fail-closed
    del tc.app.state.store._members[("community", uid)]
    ex = tc.post("/api/v1/auth/ticket/exchange", json={"ticket": ticket})
    assert ex.status_code == 401
