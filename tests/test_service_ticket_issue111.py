from __future__ import annotations

import dataclasses
import logging

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from tests.conftest import TEST_SERVICE_TOKEN, _settings

logger = logging.getLogger(__name__)

_SVC = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


@pytest.fixture
def tc():
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


def test_service_ticket_mint_and_exchange_roundtrip(tc):
    # svctkt1 is the founding signup → tenant_admin (issue #63); the second
    # registrant is a plain member — mint the ticket for THAT user.
    _register(tc, "svctkt1")
    uid = _register(tc, "svctkt1b")
    r = tc.post(
        "/api/v1/auth/ticket/service",
        headers=_SVC,
        json={"user_id": uid, "tenant_id": "community"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ticket"].startswith("fsso_")
    assert 5 <= body["expires_in"] <= 600
    # raw ticket never lands in the audit trail
    assert all("fsso_" not in str(a) for a in str(tc.app.state.store._audit))
    # exchange yields a REAL user bearer (role resolved from tenant_members)
    ex = tc.post("/api/v1/auth/ticket/exchange", json={"ticket": body["ticket"]})
    assert ex.status_code == 200, ex.text
    pair = ex.json()
    assert pair["access_token"] and pair["refresh_token"]
    v = tc.post(
        "/api/v1/auth/verify",
        json={"token": pair["access_token"]},
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"},
    )
    assert v.status_code == 200, v.text
    assert v.json()["tid"] == "community"
    assert v.json()["role"] == "member"
    # single-use: replay is uniform 401
    ex2 = tc.post("/api/v1/auth/ticket/exchange", json={"ticket": body["ticket"]})
    assert ex2.status_code == 401


def test_service_ticket_requires_service_token(tc):
    uid = _register(tc, "svctkt2")
    r = tc.post(
        "/api/v1/auth/ticket/service",
        json={"user_id": uid, "tenant_id": "community"},
    )
    assert r.status_code == 401
    # a plain user bearer is not a service credential either
    login = tc.post(
        "/api/v1/auth/login",
        json={"username": "svctkt2", "password": "Password123", "tenant_id": "community"},
    )
    assert login.status_code == 200
    bearer = {"Authorization": f"Bearer {login.json()['access_token']}"}
    r2 = tc.post(
        "/api/v1/auth/ticket/service",
        headers=bearer,
        json={"user_id": uid, "tenant_id": "community"},
    )
    assert r2.status_code == 401


def test_service_ticket_unknown_user_404(tc):
    r = tc.post(
        "/api/v1/auth/ticket/service",
        headers=_SVC,
        json={"user_id": "usr_nope", "tenant_id": "community"},
    )
    assert r.status_code == 404


def test_service_ticket_non_member_404(tc):
    uid = _register(tc, "svctkt3")
    r = tc.post(
        "/api/v1/auth/ticket/service",
        headers=_SVC,
        json={"user_id": uid, "tenant_id": "default"},
    )
    assert r.status_code == 404


def test_service_ticket_disabled_user_404(tc):
    uid = _register(tc, "svctkt4")
    store = tc.app.state.store
    user = store._users[uid]
    user["status"] = "disabled"
    r = tc.post(
        "/api/v1/auth/ticket/service",
        headers=_SVC,
        json={"user_id": uid, "tenant_id": "community"},
    )
    assert r.status_code == 404


def test_service_ticket_inactive_tenant_404(tc):
    uid = _register(tc, "svctkt5")
    store = tc.app.state.store
    store._tenants["community"]["status"] = "suspended"
    try:
        r = tc.post(
            "/api/v1/auth/ticket/service",
            headers=_SVC,
            json={"user_id": uid, "tenant_id": "community"},
        )
        assert r.status_code == 404
    finally:
        store._tenants["community"]["status"] = "active"


def test_service_ticket_audited_as_impersonation_class(tc):
    uid = _register(tc, "svctkt6")
    r = tc.post(
        "/api/v1/auth/ticket/service",
        headers=_SVC,
        json={"user_id": uid, "tenant_id": "community"},
    )
    assert r.status_code == 200
    audits = tc.app.state.store._audit
    assert any(
        a["action"] == "auth.ticket_issued.service" and a["user_id"] == uid for a in audits
    ), audits[-5:]
