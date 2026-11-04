from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from tests.conftest import TEST_SERVICE_TOKEN, _settings

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


@pytest.fixture
def reg_client(monkeypatch):
    # Verification ON (default), registration ON, capture the raw token the
    # email sender would deliver.
    captured: dict[str, Any] = {}

    async def fake_send(settings, to_email, token, username):
        captured["token"] = token
        captured["email"] = to_email
        return "logged"

    monkeypatch.setattr("fusion_identity.routes.registration.send_verification_email", fake_send)
    s = _settings()
    with TestClient(build_app(s)) as c:
        c._captured = captured
        yield c


@pytest.fixture
def noverify_client(monkeypatch):
    # Verification OFF: registration returns a token pair immediately.
    async def fake_send(settings, to_email, token, username):
        return "logged"

    monkeypatch.setattr("fusion_identity.routes.registration.send_verification_email", fake_send)
    s = dataclasses.replace(_settings(), email_verification_required=False)
    with TestClient(build_app(s)) as c:
        yield c


def test_register_returns_tokens_when_verification_off(noverify_client):
    resp = noverify_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "Password123", "email": "a@x.io"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email_verified"] is True
    tokens = body["tokens"]
    assert tokens["access_token"] and tokens["refresh_token"]
    assert body["tenant_id"] == "community"
    # the token pair is a real tenant token: verify via the service plane
    v = noverify_client.post(
        "/api/v1/auth/verify",
        json={"token": tokens["access_token"]},
        headers=_SVC_HEADERS,
    )
    assert v.status_code == 200
    assert v.json()["tid"] == "community"
    assert v.json()["role"] == "member"


def test_register_auto_creates_community_tenant_once(noverify_client, store):
    for i in range(2):
        r = noverify_client.post(
            "/api/v1/auth/register",
            json={"username": f"user{i}", "password": "Password123"},
        )
        assert r.status_code == 201
    tenants = {
        t["tenant_id"]
        for t in noverify_client.get("/api/v1/admin/tenants", headers=_SVC_HEADERS).json()
    }
    assert "community" in tenants
    # free plan template quota bound at auto-creation
    q = noverify_client.get("/api/v1/admin/tenants/community/quota", headers=_SVC_HEADERS).json()
    assert q["quota"]["rpm"] == 10


def test_register_requires_email_when_verification_on(reg_client):
    resp = reg_client.post(
        "/api/v1/auth/register", json={"username": "bob", "password": "Password123"}
    )
    assert resp.status_code == 422
    assert "email is required" in resp.json()["detail"]


def test_register_verification_blocks_login_until_verified(reg_client):
    resp = reg_client.post(
        "/api/v1/auth/register",
        json={"username": "carol", "password": "Password123", "email": "c@x.io"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "verification_required"
    assert "tokens" not in body
    # unverified login → 403 with the clear "check your inbox" state
    login = reg_client.post(
        "/api/v1/auth/login",
        json={"username": "carol", "password": "Password123", "tenant_id": "community"},
    )
    assert login.status_code == 403
    assert "email not verified" in login.json()["detail"]


def test_verify_email_flow_single_use(reg_client):
    reg_client.post(
        "/api/v1/auth/register",
        json={"username": "dave", "password": "Password123", "email": "d@x.io"},
    )
    token = reg_client._captured["token"]
    ok = reg_client.post("/api/v1/auth/verify-email", json={"token": token})
    assert ok.status_code == 200, ok.text
    assert ok.json()["verified"] is True
    # replay → 400 (single use)
    replay = reg_client.post("/api/v1/auth/verify-email", json={"token": token})
    assert replay.status_code == 400
    # now login works
    login = reg_client.post(
        "/api/v1/auth/login",
        json={"username": "dave", "password": "Password123", "tenant_id": "community"},
    )
    assert login.status_code == 200, login.text


def test_resend_verification(reg_client):
    reg_client.post(
        "/api/v1/auth/register",
        json={"username": "erin", "password": "Password123", "email": "e@x.io"},
    )
    first = reg_client._captured["token"]
    r = reg_client.post("/api/v1/auth/verify-email/resend", json={"username": "erin"})
    assert r.status_code == 200 and r.json()["resent"] is True
    second = reg_client._captured["token"]
    assert second != first
    # the first token is dead after resend (overwritten)
    assert reg_client.post("/api/v1/auth/verify-email", json={"token": first}).status_code == 400
    assert reg_client.post("/api/v1/auth/verify-email", json={"token": second}).status_code == 200
    # unknown username → same uniform response (no enumeration)
    r2 = reg_client.post("/api/v1/auth/verify-email/resend", json={"username": "ghost"})
    assert r2.status_code == 200 and r2.json()["resent"] is False


def test_register_username_conflict_409(noverify_client):
    for _ in range(2):
        r = noverify_client.post(
            "/api/v1/auth/register",
            json={"username": "same", "password": "Password123"},
        )
    assert r.status_code == 409


def test_register_disabled_by_config(monkeypatch):
    s = dataclasses.replace(_settings(), registration_enabled=False)
    with TestClient(build_app(s)) as c:
        assert (
            c.post(
                "/api/v1/auth/register", json={"username": "xx1", "password": "Password123"}
            ).status_code
            == 403
        )
        assert (
            c.post(
                "/api/v1/auth/register-tenant",
                json={
                    "tenant_display_name": "T",
                    "admin_username": "xx2",
                    "admin_password": "Password123456",
                    "admin_email": "x@x.io",
                },
            ).status_code
            == 403
        )


def test_register_tenant_full_flow(reg_client):
    resp = reg_client.post(
        "/api/v1/auth/register-tenant",
        json={
            "tenant_display_name": "Acme",
            "admin_username": "acmeadmin",
            "admin_password": "Password123456",
            "admin_email": "admin@acme.io",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    tid = body["tenant"]["tenant_id"]
    assert body["tenant"]["status"] == "active"
    assert body["tenant"]["plan"] == "free"
    assert "initial_password" not in body["admin"]
    tokens = body["tokens"]
    # admin token is a real tenant_admin token for the new tenant
    v = reg_client.post(
        "/api/v1/auth/verify", json={"token": tokens["access_token"]}, headers=_SVC_HEADERS
    )
    assert v.status_code == 200
    assert v.json()["tid"] == tid
    assert v.json()["role"] == "tenant_admin"
    # free plan quota bound at creation
    q = reg_client.get(f"/api/v1/admin/tenants/{tid}/quota", headers=_SVC_HEADERS).json()
    assert q["quota"]["rpm"] == 10
    # admin is unverified (email given, verification on) → later logins blocked
    login = reg_client.post(
        "/api/v1/auth/login",
        json={"username": "acmeadmin", "password": "Password123", "tenant_id": tid},
    )
    assert login.status_code == 403


def test_register_tenant_reuses_provision_internals(noverify_client):
    # acceptance: same store methods as the admin provision path — the tenant
    # must appear in the ordinary admin tenant list with plan + quota bound.
    resp = noverify_client.post(
        "/api/v1/auth/register-tenant",
        json={
            "tenant_display_name": "ReuseCo",
            "admin_username": "reuseadmin",
            "admin_password": "Password123456",
        },
    )
    assert resp.status_code == 201
    tid = resp.json()["tenant"]["tenant_id"]
    listed = noverify_client.get("/api/v1/admin/tenants", headers=_SVC_HEADERS).json()
    assert any(t["tenant_id"] == tid and t["plan"] == "free" for t in listed)


def test_register_tenant_idempotent_replay(reg_client):
    body = {
        "tenant_display_name": "IdemCo",
        "admin_username": "idemadmin",
        "admin_password": "Password123456",
        "admin_email": "idem@x.io",
    }
    r1 = reg_client.post(
        "/api/v1/auth/register-tenant", json=body, headers={"Idempotency-Key": "k-1"}
    )
    assert r1.status_code == 201
    r2 = reg_client.post(
        "/api/v1/auth/register-tenant", json=body, headers={"Idempotency-Key": "k-1"}
    )
    assert r2.status_code == 201
    assert r2.json()["idempotent_replay"] is True


def test_register_tenant_unknown_plan_422(reg_client):
    resp = reg_client.post(
        "/api/v1/auth/register-tenant",
        json={
            "tenant_display_name": "T",
            "admin_username": "planadmin",
            "admin_password": "Password123456",
            "admin_email": "p@x.io",
            "plan": "no-such-plan",
        },
    )
    assert resp.status_code == 422


def test_register_rate_limited(monkeypatch):
    s = dataclasses.replace(_settings(), login_rate_limit=2, login_rate_window=60)
    with TestClient(build_app(s)) as c:
        codes = [
            c.post(
                "/api/v1/auth/register",
                json={"username": f"rl{i}", "password": "Password123"},
            ).status_code
            for i in range(5)
        ]
        assert 429 in codes


def test_registration_audited(reg_client):
    reg_client.post(
        "/api/v1/auth/register",
        json={"username": "auditu", "password": "Password123", "email": "au@x.io"},
    )
    reg_client.post(
        "/api/v1/auth/register-tenant",
        json={
            "tenant_display_name": "AuditCo",
            "admin_username": "auditta",
            "admin_password": "Password123456",
            "admin_email": "at@x.io",
        },
    )
    store = reg_client.app.state.store
    actions = [r["action"] for r in store._audit]
    assert "auth.registered" in actions
    assert "auth.tenant_registered" in actions
    reg_rec = next(r for r in store._audit if r["action"] == "auth.registered")
    # password never audited
    assert "Password123" not in str(reg_rec)
