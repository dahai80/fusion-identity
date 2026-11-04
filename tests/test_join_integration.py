from __future__ import annotations

import contextlib
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

_CREATED: dict[str, list[str]] = {"tenants": [], "users": [], "invites": [], "requests": []}


@pytest.fixture
async def pg_join():
    store = PgStore(PG_URL)
    await store.connect()
    await store.ensure_schema()
    s = _settings()
    # verification OFF so test users get bearer tokens at signup directly
    import dataclasses

    s2 = dataclasses.replace(s, email_verification_required=False)
    app = build_app(s2, store=store, run_bootstrap=False)
    probe = PgStore(PG_URL)
    await probe.connect()
    with TestClient(app) as c:
        c._probe = probe
        yield c
    # cleanup (FK order: join_requests/invites → members → tenants → users)
    for rid in _CREATED["requests"]:
        with contextlib.suppress(Exception):
            await probe.execute("DELETE FROM join_requests WHERE request_id=$1", rid)
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
        with contextlib.suppress(Exception):
            await probe.execute("DELETE FROM tenant_members WHERE user_id=$1", uid)
        with contextlib.suppress(Exception):
            await probe.execute("DELETE FROM refresh_tokens WHERE user_id=$1", uid)
        with contextlib.suppress(Exception):
            await probe.execute("DELETE FROM users WHERE user_id=$1", uid)
    await probe.close()


def _login(c, username, password, tid):
    r = c.post(
        "/api/v1/auth/login", json={"username": username, "password": password, "tenant_id": tid}
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _h(token, tid):
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": tid}


def _provision(c, tid, join_policy=None):
    body = {
        "tenant_id": tid,
        "display_name": tid.title(),
        "plan": "free",
        "seed_admin": {"username": f"{tid}admin", "password": "Password123456"},
    }
    if join_policy:
        body["join_policy"] = join_policy
    r = c.post("/api/v1/admin/tenants/provision", json=body, headers=_SVC)
    assert r.status_code == 201, r.text
    _CREATED["tenants"].append(tid)
    _CREATED["users"].append(r.json()["admin"]["user_id"])
    return _login(c, f"{tid}admin", "Password123456", tid)


def _user(c, username):
    r = c.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "Password123", "email": f"{username}@x.io"},
    )
    assert r.status_code == 201, r.text
    uid = r.json()["user_id"]
    _CREATED["users"].append(uid)
    return _login(c, username, "Password123", "community")


async def test_pg_invite_join_open_flow(pg_join):
    c = pg_join
    admin = _provision(c, "pgjp1", join_policy="open")
    user_tok = _user(c, "pgjpuser1")
    r = c.post("/api/v1/auth/tenants/pgjp1/join", headers=_h(user_tok, "community"))
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "member"
    # invite mint + redeem on PG (FK: created_by/used_by → users)
    inv = c.post(
        "/api/v1/tenants/pgjp1/invites",
        json={"role": "member"},
        headers=_h(admin, "pgjp1"),
    )
    assert inv.status_code == 201, inv.text
    _CREATED["invites"].append(inv.json()["invite_id"])
    user2 = _user(c, "pgjpuser2")
    red = c.post(
        "/api/v1/auth/invites/redeem",
        json={"token": inv.json()["token"]},
        headers=_h(user2, "community"),
    )
    assert red.status_code == 200, red.text
    row = await c._probe.fetchrow(
        "SELECT used_by, role FROM tenant_invites WHERE invite_id=$1", inv.json()["invite_id"]
    )
    assert row is not None and row["role"] == "member"


async def test_pg_join_request_approve(pg_join):
    c = pg_join
    admin = _provision(c, "pgjp2", join_policy="approval")
    user_tok = _user(c, "pgjpuser3")
    sub = c.post("/api/v1/tenants/pgjp2/join-requests", headers=_h(user_tok, "community"))
    assert sub.status_code == 201, sub.text
    rid = sub.json()["request_id"]
    _CREATED["requests"].append(rid)
    ap = c.post(f"/api/v1/tenants/pgjp2/join-requests/{rid}/approve", headers=_h(admin, "pgjp2"))
    assert ap.status_code == 200, ap.text
    member = await c._probe.fetchrow(
        "SELECT role FROM tenant_members WHERE tenant_id=$1 AND user_id=$2",
        "pgjp2",
        ap.json()["user_id"],
    )
    assert member is not None and member["role"] == "member"
