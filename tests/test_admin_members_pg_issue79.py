from __future__ import annotations

import contextlib

import pytest

from tests.test_acceptance_issue71 import PG_URL

_TENANT = "pgadm79"
_USERS = ["u79admin", "u79probe"]


@pytest.fixture
async def admin_pg():
    from fusion_identity.db import PgStore

    store = PgStore(PG_URL)
    await store.connect()
    await store.ensure_schema()
    cleanup = [
        "DELETE FROM audit_log WHERE tenant_id=$1",
        "DELETE FROM service_accounts WHERE tenant_id=$1",
        "DELETE FROM issued_jtis WHERE tenant_id=$1",
        "DELETE FROM event_outbox WHERE tenant_id=$1",
        "DELETE FROM usage_ledger WHERE tenant_id=$1",
        "DELETE FROM lease_log WHERE tenant_id=$1",
        "DELETE FROM api_keys WHERE tenant_id=$1",
        "DELETE FROM quotas WHERE tenant_id=$1",
        "DELETE FROM tenant_members WHERE tenant_id=$1",
        "DELETE FROM tenants WHERE tenant_id=$1",
    ]
    for sql in cleanup:
        with contextlib.suppress(Exception):
            await store.execute(sql, _TENANT)
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM users WHERE user_id = ANY($1)", _USERS)
    await store.create_tenant(_TENANT, "Issue 79 Admin Members")
    yield store
    for sql in cleanup:
        with contextlib.suppress(Exception):
            await store.execute(sql, _TENANT)
    with contextlib.suppress(Exception):
        await store.execute("DELETE FROM users WHERE user_id = ANY($1)", _USERS)
    await store.close()


@pytest.mark.integration
async def test_pg_admin_list_and_remove(admin_pg):
    store = admin_pg
    await store.create_user(_USERS[0], "u79admin", "password-long-79", "u79a@x.io")
    await store.create_user(_USERS[1], "u79probe", "password-long-79", "u79p@x.io")
    await store.add_member(_TENANT, _USERS[0], "tenant_admin", None)
    await store.add_member(_TENANT, _USERS[1], "member", None)

    out = await store.admin_list_members(_TENANT)
    assert out["total"] == 2
    by_name = {i["username"]: i for i in out["items"]}
    assert by_name["u79admin"]["role"] == "tenant_admin"
    assert by_name["u79probe"]["status"] == "active"
    assert by_name["u79admin"]["user_id"] == _USERS[0]

    page = await store.admin_list_members(_TENANT, limit=1, offset=1)
    assert page["total"] == 2 and len(page["items"]) == 1

    assert await store.remove_member(_TENANT, _USERS[1]) is True
    out = await store.admin_list_members(_TENANT)
    assert out["total"] == 1 and out["items"][0]["username"] == "u79admin"


@pytest.mark.integration
async def test_pg_admin_member_routes_http(admin_pg):
    import dataclasses

    from starlette.testclient import TestClient

    from fusion_identity.app import build_app
    from fusion_identity.db import PgStore
    from tests.conftest import TEST_SERVICE_TOKEN, _settings

    await admin_pg.create_user(_USERS[0], "u79admin", "password-long-79", "u79a@x.io")
    await admin_pg.create_user(_USERS[1], "u79probe", "password-long-79", "u79p@x.io")
    await admin_pg.add_member(_TENANT, _USERS[0], "tenant_admin", None)
    await admin_pg.add_member(_TENANT, _USERS[1], "member", None)

    # asyncpg pools are loop-bound: the HTTP app gets its OWN unconnected
    # store (app startup connects it on the TestClient portal loop).
    http_store = PgStore(PG_URL)
    s = dataclasses.replace(_settings(), redis_url="", grpc_port=0)
    app = build_app(s, store=http_store, run_bootstrap=False)
    headers = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"}
    with TestClient(app) as http:
        r = http.get(f"/api/v1/admin/tenants/{_TENANT}/members", headers=headers)
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["total"] == 2
        users = {i["username"]: i for i in out["items"]}
        assert users["u79probe"]["role"] == "member"

        # Last-admin guard on the live PG path.
        r = http.delete(f"/api/v1/admin/tenants/{_TENANT}/members/{_USERS[0]}", headers=headers)
        assert r.status_code == 403
        assert "last tenant_admin" in r.json()["detail"]

        # Remove the probe member; audit row rides the hash chain.
        r = http.delete(f"/api/v1/admin/tenants/{_TENANT}/members/{_USERS[1]}", headers=headers)
        assert r.status_code == 200 and r.json()["removed"] is True
        rows = await admin_pg.fetch(
            "SELECT action, role FROM audit_log WHERE tenant_id=$1 AND action='member.remove'",
            _TENANT,
        )
        assert len(rows) == 1 and rows[0]["role"] == "service"
