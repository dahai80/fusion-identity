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
async def pg_login():
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
            "DELETE FROM tenant_members WHERE user_id=$1",
            "DELETE FROM refresh_tokens WHERE user_id=$1",
            "DELETE FROM issued_jtis WHERE user_id=$1",
            "DELETE FROM audit_log WHERE user_id=$1",
            "DELETE FROM users WHERE user_id=$1",
        ):
            with contextlib.suppress(Exception):
                await probe.execute(sql, uid)
    await probe.close()


def _login(c, username, password, tid=None):
    body = {"username": username, "password": password}
    if tid is not None:
        body["tenant_id"] = tid
    return c.post("/api/v1/auth/login", json=body)


def _register(c, username):
    r = c.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "Password123", "email": f"{username}@x.io"},
    )
    assert r.status_code == 201, r.text
    uid = r.json()["user_id"]
    _CREATED["users"].append(uid)
    return uid


def _provision(c, tid):
    r = c.post(
        "/api/v1/admin/tenants/provision",
        json={
            "tenant_id": tid,
            "display_name": tid.title(),
            "plan": "free",
            "seed_admin": {"username": f"{tid}admin", "password": "Password123456"},
        },
        headers=_SVC,
    )
    assert r.status_code == 201, r.text
    _CREATED["tenants"].append(tid)
    _CREATED["users"].append(r.json()["admin"]["user_id"])
    return _login(c, f"{tid}admin", "Password123456", tid).json()["access_token"]


async def test_pg_login_without_tenant(pg_login):
    c = pg_login
    uid = _register(c, "pglr1")
    r = _login(c, "pglr1", "Password123")
    assert r.status_code == 200, r.text
    v = c.post("/api/v1/auth/verify", json={"token": r.json()["access_token"]}, headers=_SVC)
    assert v.status_code == 200, v.text
    assert v.json()["tid"] == "community"
    logger.info("pg tenant-less login ok uid=%s", uid)


async def test_pg_wrong_tenant_tenant_mismatch(pg_login):
    c = pg_login
    _register(c, "pglr2")
    _provision(c, "pglrother")
    r = _login(c, "pglr2", "Password123", "pglrother")
    assert r.status_code == 401
    assert r.json()["detail"] == "tenant_mismatch"
