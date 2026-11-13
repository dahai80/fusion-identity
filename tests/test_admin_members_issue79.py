from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN


@pytest.fixture
def svc_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"}


@pytest.fixture
def seeded(client: TestClient) -> dict[str, str]:
    # Fresh tenant via register-tenant (returns the admin token pair), then a
    # second member added through the member plane.
    r = client.post(
        "/api/v1/auth/register-tenant",
        json={
            "tenant_display_name": "Alt 79",
            "admin_username": "admin79",
            "admin_password": "admin-pass-79",
            "admin_email": "admin79@x.io",
            "plan": "free",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    tid = body["tenant"]["tenant_id"]
    admin_tok = body["tokens"]["access_token"]
    r = client.post(
        f"/api/v1/tenants/{tid}/members",
        json={"username": "probe79", "password": "probe-pass-79", "role": "member"},
        headers={"Authorization": f"Bearer {admin_tok}", "X-Tenant-Id": tid},
    )
    assert r.status_code in (200, 201), r.text
    return {"tenant_id": tid, "admin_token": admin_tok}


async def test_admin_list_and_remove_member(client: TestClient, seeded, svc_headers):
    tid = seeded["tenant_id"]
    # Enumeration: identity fields present, not counts-only.
    r = client.get(f"/api/v1/admin/tenants/{tid}/members", headers=svc_headers)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["total"] == 2
    users = {i["username"]: i for i in out["items"]}
    assert set(users) == {"admin79", "probe79"}
    assert users["admin79"]["role"] == "tenant_admin"
    assert users["probe79"]["role"] == "member"
    assert all(i["user_id"].startswith("usr_") for i in out["items"])
    assert all(i["status"] == "active" for i in out["items"])

    # Pagination.
    r = client.get(
        f"/api/v1/admin/tenants/{tid}/members",
        params={"limit": 1, "offset": 1},
        headers=svc_headers,
    )
    assert r.status_code == 200 and len(r.json()["items"]) == 1 and r.json()["total"] == 2

    # Unknown tenant 404.
    assert (
        client.get("/api/v1/admin/tenants/nope79/members", headers=svc_headers).status_code == 404
    )

    # Remove the probe member (service plane, no member JWT involved).
    uid = users["probe79"]["user_id"]
    r = client.delete(f"/api/v1/admin/tenants/{tid}/members/{uid}", headers=svc_headers)
    assert r.status_code == 200 and r.json()["removed"] is True
    # Replay: 404 — member gone.
    assert (
        client.delete(f"/api/v1/admin/tenants/{tid}/members/{uid}", headers=svc_headers).status_code
        == 404
    )
    # Unknown tenant on delete: 404.
    assert (
        client.delete(
            f"/api/v1/admin/tenants/nope79/members/{uid}", headers=svc_headers
        ).status_code
        == 404
    )
    # Inventory reflects removal; audit row written by the service principal.
    out = client.get(f"/api/v1/admin/tenants/{tid}/members", headers=svc_headers).json()
    assert out["total"] == 1
    audit = client.get(
        f"/api/v1/tenants/{tid}/audit",
        headers={"Authorization": f"Bearer {seeded['admin_token']}", "X-Tenant-Id": tid},
    ).json()
    assert any(e["action"] == "member.remove" and e["role"] == "service" for e in audit)


async def test_admin_remove_last_admin_blocked(client: TestClient, seeded, svc_headers):
    # Same fail-closed rule as the member plane: purge cannot strip the final
    # tenant_admin of a tenant.
    tid = seeded["tenant_id"]
    out = client.get(f"/api/v1/admin/tenants/{tid}/members", headers=svc_headers).json()
    admins = [i for i in out["items"] if i["role"] == "tenant_admin"]
    assert len(admins) == 1
    r = client.delete(
        f"/api/v1/admin/tenants/{tid}/members/{admins[0]['user_id']}", headers=svc_headers
    )
    assert r.status_code == 403
    assert "last tenant_admin" in r.json()["detail"]


async def test_admin_member_requires_service_token(client: TestClient, seeded):
    tid = seeded["tenant_id"]
    # No bearer -> 401; a member JWT is not sufficient on the admin plane.
    assert client.get(f"/api/v1/admin/tenants/{tid}/members").status_code == 401
