from __future__ import annotations

import contextlib
import dataclasses
import logging
import os

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.db import PgStore
from tests.conftest import TEST_SERVICE_TOKEN, _settings

logger = logging.getLogger(__name__)

PG_URL = os.environ.get(
    "FUSION_IDENTITY_DATABASE_URL",
    "postgresql://postgres:pgpassword@127.0.0.1:5433/fusion_identity",
)

pytestmark = pytest.mark.integration

_SVC = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"}

_CREATED: dict[str, list[str]] = {"tenants": [], "users": []}


@pytest.fixture
async def pg_sso():
    store = PgStore(PG_URL)
    await store.connect()
    await store.ensure_schema()
    s = dataclasses.replace(_settings(), email_verification_required=False)
    app = build_app(s, store=store, run_bootstrap=False)
    probe = PgStore(PG_URL)
    await probe.connect()
    with TestClient(app) as c:
        c._probe = probe
        yield c
    for tid in _CREATED["tenants"]:
        for sql in (
            "DELETE FROM sso_tickets WHERE tenant_id=$1",
            "DELETE FROM tenant_invites WHERE tenant_id=$1",
            "DELETE FROM join_requests WHERE tenant_id=$1",
            "DELETE FROM tenant_members WHERE tenant_id=$1",
            "DELETE FROM quotas WHERE tenant_id=$1",
            "DELETE FROM event_outbox WHERE tenant_id=$1",
            "DELETE FROM audit_log WHERE tenant_id=$1",
            "DELETE FROM issued_jtis WHERE tenant_id=$1",
            "DELETE FROM revoked_jtis WHERE tenant_id=$1",
            "DELETE FROM refresh_tokens WHERE tenant_id=$1",
            "DELETE FROM api_keys WHERE tenant_id=$1",
            "DELETE FROM tenants WHERE tenant_id=$1",
        ):
            with contextlib.suppress(Exception):
                await probe.execute(sql, tid)
    for uid in _CREATED["users"]:
        for sql in (
            "DELETE FROM sso_tickets WHERE user_id=$1",
            "DELETE FROM tenant_members WHERE user_id=$1",
            "DELETE FROM refresh_tokens WHERE user_id=$1",
            "DELETE FROM issued_jtis WHERE user_id=$1",
            "DELETE FROM audit_log WHERE user_id=$1",
            "DELETE FROM users WHERE user_id=$1",
        ):
            with contextlib.suppress(Exception):
                await probe.execute(sql, uid)
    await probe.close()


def _register(c, username):
    r = c.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "Password123", "email": f"{username}@x.io"},
    )
    assert r.status_code == 201, r.text
    uid = r.json()["user_id"]
    _CREATED["users"].append(uid)
    return uid


def _login(c, username, password, tid):
    r = c.post(
        "/api/v1/auth/login", json={"username": username, "password": password, "tenant_id": tid}
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


async def test_pg_sso_ticket_roundtrip(pg_sso):
    c = pg_sso
    uid = _register(c, "pgsso1")
    tok = _login(c, "pgsso1", "Password123", "community")
    r = c.post(
        "/api/v1/auth/ticket",
        headers={"Authorization": f"Bearer {tok}", "X-Tenant-Id": "community"},
    )
    assert r.status_code == 200, r.text
    ticket = r.json()["ticket"]
    row = await c._probe.fetchrow("SELECT used_at FROM sso_tickets")
    assert row is not None and row["used_at"] is None
    ex = c.post("/api/v1/auth/ticket/exchange", json={"ticket": ticket})
    assert ex.status_code == 200, ex.text
    pair = ex.json()
    v = c.post("/api/v1/auth/verify", json={"token": pair["access_token"]}, headers=_SVC)
    assert v.status_code == 200, v.text
    assert v.json()["tid"] == "community"
    # replay rejected on PG (used_at set)
    replay = c.post("/api/v1/auth/ticket/exchange", json={"ticket": ticket})
    assert replay.status_code == 401
    row = await c._probe.fetchrow("SELECT used_at FROM sso_tickets WHERE user_id=$1", uid)
    assert row is not None and row["used_at"] is not None
    logger.info("pg sso roundtrip ok uid=%s", uid)
