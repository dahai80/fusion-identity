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


def test_rbac_member_cannot_create_tenant_403(client: TestClient):
    admin_token = _admin(client)
    cm = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "m1", "password": "pw12345", "role": "member"},
        headers=_hdr(admin_token),
    )
    assert cm.status_code == 201, cm.text

    member_token = client.post(
        "/api/v1/auth/login",
        json={"username": "m1", "password": "pw12345", "tenant_id": "default"},
    ).json()["access_token"]

    resp = client.post(
        "/api/v1/tenants",
        json={"tenant_id": "x", "display_name": "X"},
        headers=_hdr(member_token),
    )
    assert resp.status_code == 403, resp.text


def test_rbac_viewer_cannot_manage_members(client: TestClient):
    admin_token = _admin(client)
    cm = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "v1", "password": "pw12345", "role": "viewer"},
        headers=_hdr(admin_token),
    )
    assert cm.status_code == 201, cm.text

    viewer_token = client.post(
        "/api/v1/auth/login",
        json={"username": "v1", "password": "pw12345", "tenant_id": "default"},
    ).json()["access_token"]

    resp = client.get("/api/v1/tenants/default/members", headers=_hdr(viewer_token))
    assert resp.status_code == 403, resp.text


def test_rbac_admin_can_create_api_key(client: TestClient):
    admin_token = _admin(client)
    resp = client.post(
        "/api/v1/tenants/default/api-keys",
        json={"scopes": ["models:read"]},
        headers=_hdr(admin_token),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["key_id"]
    assert body["raw_key"]
    assert body["scopes"] == ["models:read"]
