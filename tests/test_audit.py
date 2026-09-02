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


def test_audit_records_login(client: TestClient):
    token = _admin(client)
    resp = client.get("/api/v1/tenants/default/audit", headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert any(r.get("action") == "auth.login" for r in rows)


def test_audit_self_query_only(client: TestClient):
    admin_token = _admin(client)

    resp = client.get("/api/v1/tenants/other/audit", headers=_hdr(admin_token, tenant="default"))
    assert resp.status_code == 403, resp.text


def test_audit_limit_bounds(client: TestClient):
    token = _admin(client)
    resp = client.get("/api/v1/tenants/default/audit", params={"limit": 0}, headers=_hdr(token))
    assert resp.status_code == 400, resp.text
    resp = client.get("/api/v1/tenants/default/audit", params={"limit": 9999}, headers=_hdr(token))
    assert resp.status_code == 400, resp.text
