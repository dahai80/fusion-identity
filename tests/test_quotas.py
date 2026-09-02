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


def test_quota_update_hot_no_restart(client: TestClient):
    token = _admin(client)
    before = client.get("/api/v1/tenants/default/quotas", headers=_hdr(token))
    assert before.status_code == 200, before.text
    assert before.json()["rpm"] == 60

    put = client.put(
        "/api/v1/tenants/default/quotas", json={"rpm": 200, "tpm": 500000}, headers=_hdr(token)
    )
    assert put.status_code == 200, put.text
    assert put.json()["rpm"] == 200
    assert put.json()["tpm"] == 500000

    after = client.get("/api/v1/tenants/default/quotas", headers=_hdr(token))
    assert after.json()["rpm"] == 200
    assert after.json()["tpm"] == 500000


def test_quota_cross_tenant_blocked(client: TestClient):
    token = _admin(client)

    resp = client.put(
        "/api/v1/tenants/other/quotas", json={"rpm": 999}, headers=_hdr(token, tenant="default")
    )
    assert resp.status_code == 403, resp.text


def test_quota_empty_update_rejects_400(client: TestClient):
    token = _admin(client)
    resp = client.put("/api/v1/tenants/default/quotas", json={}, headers=_hdr(token))
    assert resp.status_code == 400, resp.text
