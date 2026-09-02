from __future__ import annotations

import logging

from starlette.testclient import TestClient

logger = logging.getLogger(__name__)


def _admin(client: TestClient) -> str:
    return client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]


def _hdr(token: str, tenant: str = "default") -> dict:
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": tenant}


def test_tenant_admin_list_tenants(client: TestClient):
    token = _admin(client)
    resp = client.get("/api/v1/tenants", headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    assert any(t["tenant_id"] == "default" for t in resp.json())


def test_create_tenant_requires_admin_header(client: TestClient):
    token = _admin(client)
    resp = client.post(
        "/api/v1/tenants",
        json={"tenant_id": "t2", "display_name": "T2"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_cross_tenant_admin_blocked_from_other_tenant_members(client: TestClient):
    token = _admin(client)
    create = client.post(
        "/api/v1/tenants", json={"tenant_id": "acme", "display_name": "Acme"}, headers=_hdr(token)
    )
    assert create.status_code == 201, create.text

    resp = client.get("/api/v1/tenants/acme/members", headers=_hdr(token, tenant="default"))
    assert resp.status_code == 403, resp.text


def test_member_cannot_create_tenant_403(client: TestClient):
    admin_token = _admin(client)
    create_member = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "viewer1", "password": "pw12345", "role": "viewer"},
        headers=_hdr(admin_token),
    )
    assert create_member.status_code == 201, create_member.text

    member_token = client.post(
        "/api/v1/auth/login",
        json={"username": "viewer1", "password": "pw12345", "tenant_id": "default"},
    ).json()["access_token"]

    resp = client.post(
        "/api/v1/tenants",
        json={"tenant_id": "rogue", "display_name": "Rogue"},
        headers=_hdr(member_token),
    )
    assert resp.status_code == 403, resp.text
