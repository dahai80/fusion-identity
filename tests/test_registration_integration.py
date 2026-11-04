from __future__ import annotations

import contextlib
import logging
import os

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.db import PgStore
from tests.conftest import _settings

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
    assert member["role"] == "member"
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
