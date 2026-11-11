from __future__ import annotations

import contextlib
import logging
import os

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.db import PgStore
from tests.conftest import TEST_SERVICE_TOKEN, _settings

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}

logger = logging.getLogger(__name__)

PG_URL = os.environ.get(
    "FUSION_IDENTITY_DATABASE_URL",
    "postgresql://postgres:pgpassword@127.0.0.1:5433/fusion_identity",
)

pytestmark = pytest.mark.integration

_CREATED_USERS: list[str] = []
_CREATED_TENANTS: list[str] = []


async def _cleanup(store):
    for tid in _CREATED_TENANTS:
        for sql in (
            "DELETE FROM tenant_members WHERE tenant_id=$1",
            "DELETE FROM quotas WHERE tenant_id=$1",
            "DELETE FROM idempotency_keys WHERE tenant_id=$1",
            "DELETE FROM tenants WHERE tenant_id=$1",
        ):
            with contextlib.suppress(Exception):
                await store.execute(sql, tid)
    for uid in _CREATED_USERS:
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM tenant_members WHERE user_id=$1", uid)
        with contextlib.suppress(Exception):
            await store.execute("DELETE FROM users WHERE user_id=$1", uid)
    # Sweep-pattern fallback (leftover rows from a crashed prior run).
    # tenant_members.added_by self-references users, so members referencing
    # these users (either column) must go before the users themselves.
    for sql in (
        "DELETE FROM api_keys WHERE user_id IN"
        " (SELECT user_id FROM users WHERE username LIKE 'pgreg%')",
        "DELETE FROM user_mfa WHERE user_id IN"
        " (SELECT user_id FROM users WHERE username LIKE 'pgreg%')",
        "DELETE FROM refresh_tokens WHERE user_id IN"
        " (SELECT user_id FROM users WHERE username LIKE 'pgreg%')",
        "DELETE FROM tenant_members WHERE user_id IN"
        " (SELECT user_id FROM users WHERE username LIKE 'pgreg%')",
        "DELETE FROM tenant_members WHERE added_by IN"
        " (SELECT user_id FROM users WHERE username LIKE 'pgreg%')",
        "DELETE FROM users WHERE username LIKE 'pgreg%'",
        "DELETE FROM quotas WHERE tenant_id='community'",
        "DELETE FROM tenant_members WHERE tenant_id='community'",
        "DELETE FROM tenants WHERE tenant_id='community' OR tenant_id LIKE 'pgreg%'",
    ):
        with contextlib.suppress(Exception):
            await store.execute(sql)


@pytest.fixture
async def pg_client():
    store = PgStore(PG_URL)
    await store.connect()
    await store.ensure_schema()
    await _cleanup(store)
    s = _settings()
    # The app owns (and closes on shutdown) its own pool; assertions and
    # cleanup use a separate one so app teardown never pulls the rug out.
    app = build_app(s, store=store, run_bootstrap=False)
    probe = PgStore(PG_URL)
    await probe.connect()
    with TestClient(app) as c:
        c._store = probe
        yield c
    await _cleanup(probe)
    await probe.close()


def _track(resp):
    body = resp.json()
    uid = (
        (body.get("user_id") or (body.get("admin") or {}).get("user_id"))
        if isinstance(body, dict)
        else None
    )
    if uid:
        _CREATED_USERS.append(uid)
    if isinstance(body, dict):
        tid = (body.get("tenant") or {}).get("tenant_id") or body.get("tenant_id")
        if tid:
            _CREATED_TENANTS.append(tid)
    return body


async def test_pg_register_personal_fk_holds(pg_client, monkeypatch):
    # Regression: tenant_members.added_by is FK-attributed to users(user_id);
    # a literal "registration" violates the constraint on Postgres (InMemory
    # cannot catch FK bugs). The self-registered user joins under their own id.
    async def fake_send(settings, to_email, token, username):
        return "logged"

    monkeypatch.setattr("fusion_identity.routes.registration.send_verification_email", fake_send)
    # Issue #63 made the role order-dependent: when this test runs FIRST
    # (pytest-randomly) the community tenant may not exist yet, and this
    # signup then FOUNDs it as tenant_admin. Assert the role consistent with
    # the pre-existing state; the FK assertion is the actual target here.
    community_existed = (
        await pg_client._store.fetchval("SELECT status FROM tenants WHERE tenant_id='community'")
        is not None
    )
    r = pg_client.post(
        "/api/v1/auth/register",
        json={"username": "pgreguser1", "password": "Password123", "email": "pgreg1@example.com"},
    )
    assert r.status_code == 201, r.text
    body = _track(r)
    member = await pg_client._store.fetchrow(
        "SELECT role, added_by FROM tenant_members WHERE user_id=$1",
        body["user_id"],
    )
    assert member is not None
    expected_role = "member" if community_existed else "tenant_admin"
    assert member["role"] == expected_role
    assert member["added_by"] == body["user_id"]


async def test_pg_register_tenant_fk_holds(pg_client, monkeypatch):
    async def fake_send(settings, to_email, token, username):
        return "logged"

    monkeypatch.setattr("fusion_identity.routes.registration.send_verification_email", fake_send)
    r = pg_client.post(
        "/api/v1/auth/register-tenant",
        json={
            "tenant_display_name": "PgReg Tenant",
            "admin_username": "pgregadmin1",
            "admin_password": "Password123456",
            "admin_email": "pgregadmin1@example.com",
        },
    )
    assert r.status_code == 201, r.text
    body = _track(r)
    admin_uid = body["admin"]["user_id"]
    member = await pg_client._store.fetchrow(
        "SELECT role, added_by FROM tenant_members WHERE user_id=$1", admin_uid
    )
    assert member is not None
    assert member["role"] == "tenant_admin"


async def test_pg_verify_email_roundtrip(pg_client, monkeypatch):
    captured: dict = {}

    async def fake_send(settings, to_email, token, username):
        captured["token"] = token
        return "logged"

    monkeypatch.setattr("fusion_identity.routes.registration.send_verification_email", fake_send)
    r = pg_client.post(
        "/api/v1/auth/register",
        json={"username": "pgreguser2", "password": "Password123", "email": "pgreg2@example.com"},
    )
    assert r.status_code == 201, r.text
    _track(r)
    token = captured["token"]
    v = pg_client.post("/api/v1/auth/verify-email", json={"token": token})
    assert v.status_code == 200, v.text
    assert v.json()["verified"] is True
    replay = pg_client.post("/api/v1/auth/verify-email", json={"token": token})
    assert replay.status_code == 400


async def test_pg_register_tenant_admin_verified_two_logins(pg_client, monkeypatch):
    # Issue #66 acceptance: with email verification enforced, register-tenant
    # seeds the admin VERIFIED — a second login without any email redemption
    # must succeed (no SMTP lockout).
    r = pg_client.post(
        "/api/v1/auth/register-tenant",
        json={
            "tenant_display_name": "Pg66 Tenant",
            "admin_username": "pgregadmin66",
            "admin_password": "Password123456",
            "admin_email": "pgregadmin66@example.com",
        },
    )
    assert r.status_code == 201, r.text
    body = _track(r)
    tid = body["tenant"]["tenant_id"]
    uid = await pg_client._store.fetchval(
        "SELECT email_verified FROM users WHERE user_id=$1", body["admin"]["user_id"]
    )
    assert uid is True
    for _ in range(2):
        login = pg_client.post(
            "/api/v1/auth/login",
            json={"username": "pgregadmin66", "password": "Password123456", "tenant_id": tid},
        )
        assert login.status_code == 200, login.text


async def test_pg_first_member_of_auto_tenant_is_admin(pg_client, monkeypatch):
    # Issue #63 acceptance: a freshly auto-created open-join tenant has at
    # least one tenant_admin (its first member). Drop any community tenant
    # left by earlier tests so THIS signup is the founding one.
    for sql in (
        "DELETE FROM tenant_members WHERE tenant_id='community'",
        "DELETE FROM quotas WHERE tenant_id='community'",
        "DELETE FROM event_outbox WHERE tenant_id='community'",
        "DELETE FROM audit_log WHERE tenant_id='community'",
        "DELETE FROM issued_jtis WHERE tenant_id='community'",
        "DELETE FROM revoked_jtis WHERE tenant_id='community'",
        "DELETE FROM refresh_tokens WHERE tenant_id='community'",
        "DELETE FROM sso_tickets WHERE tenant_id='community'",
        "DELETE FROM tenant_invites WHERE tenant_id='community'",
        "DELETE FROM join_requests WHERE tenant_id='community'",
        "DELETE FROM api_keys WHERE tenant_id='community'",
        "DELETE FROM tenants WHERE tenant_id='community'",
    ):
        with contextlib.suppress(Exception):
            await pg_client._store.execute(sql)
    r = pg_client.post(
        "/api/v1/auth/register",
        json={
            "username": "pgregfirst66",
            "password": "Password123",
            "email": "pgregfirst66@example.com",
        },
    )
    assert r.status_code == 201, r.text
    body = _track(r)
    member = await pg_client._store.fetchrow(
        "SELECT role FROM tenant_members WHERE user_id=$1 AND tenant_id='community'",
        body["user_id"],
    )
    assert member is not None and member["role"] == "tenant_admin"
    # Elevation endpoint promotes an existing member on real PG.
    r2 = pg_client.post(
        "/api/v1/auth/register",
        json={
            "username": "pgregsecond66",
            "password": "Password123",
            "email": "pgregsecond66@example.com",
        },
    )
    assert r2.status_code == 201, r2.text
    uid2 = _track(r2)["user_id"]
    r = pg_client.post(
        "/api/v1/admin/tenants/community/admins", json={"user_id": uid2}, headers=_SVC_HEADERS
    )
    assert r.status_code == 200 and r.json()["changed"] is True
    role = await pg_client._store.fetchval(
        "SELECT role FROM tenant_members WHERE user_id=$1 AND tenant_id='community'", uid2
    )
    assert role == "tenant_admin"
