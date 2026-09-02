from __future__ import annotations

import logging

from starlette.testclient import TestClient

logging.getLogger(__name__)

TEST_SERVICE_TOKEN = "test-service-token"


def _hdr(token: str, tenant: str = "default") -> dict:
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": tenant}


def _svc_hdr(tenant: str = "default") -> dict:
    return {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": tenant}


def _admin(client: TestClient) -> str:
    return client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]


def test_emit_usage_service_token(client: TestClient):
    resp = client.post(
        "/api/v1/tenants/default/usage",
        json={"metric": "requests", "value": 10, "source": "fusion-mlx", "model": "qwen"},
        headers=_svc_hdr(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"metric": "requests", "value": 10}


def test_emit_usage_requires_service_token(client: TestClient):
    token = _admin(client)
    resp = client.post(
        "/api/v1/tenants/default/usage",
        json={"metric": "requests", "value": 1, "source": "x"},
        headers=_hdr(token),
    )
    assert resp.status_code == 401, resp.text


def test_emit_usage_unknown_tenant_404(client: TestClient):
    resp = client.post(
        "/api/v1/tenants/ghost/usage",
        json={"metric": "requests", "value": 1, "source": "x"},
        headers=_svc_hdr("ghost"),
    )
    assert resp.status_code == 404, resp.text


def test_get_usage_aggregates(client: TestClient):
    for v in (5, 7, 3):
        client.post(
            "/api/v1/tenants/default/usage",
            json={"metric": "requests", "value": v, "source": "s"},
            headers=_svc_hdr(),
        )
    client.post(
        "/api/v1/tenants/default/usage",
        json={"metric": "tokens", "value": 100, "source": "s"},
        headers=_svc_hdr(),
    )
    token = _admin(client)
    resp = client.get("/api/v1/tenants/default/usage", headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    rows = {r["metric"]: r["value"] for r in resp.json()}
    assert rows["requests"] == 15
    assert rows["tokens"] == 100


def test_get_usage_requires_admin(client: TestClient):
    resp = client.get(
        "/api/v1/tenants/default/usage",
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "default"},
    )
    assert resp.status_code == 401, resp.text


def test_cross_tenant_usage_blocked(client: TestClient):
    token = _admin(client)
    resp = client.get("/api/v1/tenants/other/usage", headers=_hdr(token, "default"))
    assert resp.status_code == 403, resp.text


def test_get_tenant_config(client: TestClient):
    token = _admin(client)
    resp = client.get("/api/v1/tenants/default/config", headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == "default"
    assert "quota" in body
    assert "rpm" in body["quota"]


def test_export_tenant_strips_secrets(client: TestClient):
    token = _admin(client)
    client.post(
        "/api/v1/tenants/default/usage",
        json={"metric": "requests", "value": 1, "source": "s"},
        headers=_svc_hdr(),
    )
    resp = client.get("/api/v1/tenants/default/export", headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant"]["tenant_id"] == "default"
    for m in body["members"]:
        assert "password_hash" not in m
        assert "salt" not in m
    assert "usage" in body
