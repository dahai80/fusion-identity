from __future__ import annotations

from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


def admin_token_for(client: TestClient) -> str:
    return client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]


def test_admin_create_tenant_and_key(client: TestClient):
    resp = client.post(
        "/api/v1/admin/tenants",
        json={"tenant_id": "acme2", "display_name": "Acme2", "plan": "enterprise"},
        headers=_SVC_HEADERS,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["tenant_id"] == "acme2"

    resp = client.post(
        "/api/v1/admin/tenants",
        json={"tenant_id": "acme2", "display_name": "dup", "plan": "standard"},
        headers=_SVC_HEADERS,
    )
    assert resp.status_code == 409

    kresp = client.post(
        "/api/v1/admin/tenants/acme2/api-keys",
        json={"scopes": ["inference"]},
        headers=_SVC_HEADERS,
    )
    assert kresp.status_code == 201, kresp.text
    body = kresp.json()
    assert body["raw_key"].startswith("fmu_")
    assert "key_hash" not in body


def test_admin_requires_service_token(client: TestClient):
    resp = client.get("/api/v1/admin/tenants", headers={"X-Tenant-Id": "_system"})
    assert resp.status_code == 401
    resp = client.get(
        "/api/v1/admin/tenants",
        headers={"Authorization": "Bearer wrong", "X-Tenant-Id": "_system"},
    )
    assert resp.status_code == 401


def test_admin_list_tenants(client: TestClient):
    resp = client.get("/api/v1/admin/tenants", headers=_SVC_HEADERS)
    assert resp.status_code == 200
    ids = [t["tenant_id"] for t in resp.json()]
    assert "default" in ids


def test_admin_usage_today(client: TestClient):
    client.post(
        "/api/v1/tenants/default/usage",
        json={"metric": "tokens", "value": 500, "source": "test"},
        headers=_SVC_HEADERS,
    )
    resp = client.get("/api/v1/admin/tenants/default/usage/today", headers=_SVC_HEADERS)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "concurrency" in body
    assert body["concurrency"]["max_limit"] >= 0
    assert "tokens" in body
    assert body["tokens"]["total_today"] >= 500
    assert body["tokens"]["daily_limit"] > 0
    assert "usage_percentage" in body["tokens"]


def test_admin_update_tenant_quota(client: TestClient):
    resp = client.put(
        "/api/v1/admin/tenants/default",
        json={"max_concurrency": 8, "daily_token_limit": 200000},
        headers=_SVC_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    h = {"Authorization": f"Bearer {admin_token_for(client)}", "X-Tenant-Id": "default"}
    q = client.get("/api/v1/tenants/default/quotas", headers=h).json()
    assert q["concurrent"] == 8
    assert q["tpm"] == 200000


def test_admin_create_tenant_with_quota(client: TestClient):
    resp = client.post(
        "/api/v1/admin/tenants",
        json={
            "tenant_id": "quota-tenant",
            "display_name": "Quota Tenant",
            "plan": "enterprise",
            "max_concurrency": 16,
            "daily_token_limit": 999999,
            "allowed_modules": ["code"],
            "allowed_models": ["gpt-4"],
        },
        headers=_SVC_HEADERS,
    )
    assert resp.status_code == 201, resp.text
    q = client.get("/api/v1/admin/tenants/quota-tenant/quota", headers=_SVC_HEADERS).json()
    assert q["quota"]["concurrent"] == 16
    assert q["quota"]["tpm"] == 999999
    assert q["quota"]["allowed_modules"] == ["code"]
    assert q["quota"]["allowed_models"] == ["gpt-4"]


def test_admin_revoke_api_key_keys_alias(client: TestClient):
    kresp = client.post(
        "/api/v1/admin/tenants/default/keys",
        json={"scopes": ["inference"]},
        headers=_SVC_HEADERS,
    )
    assert kresp.status_code == 201, kresp.text
    key_id = kresp.json()["key_id"]
    rev = client.delete(
        f"/api/v1/admin/tenants/default/keys/{key_id}",
        headers=_SVC_HEADERS,
    )
    assert rev.status_code == 200, rev.text
    assert rev.json()["revoked"] is True
    again = client.delete(
        f"/api/v1/admin/tenants/default/keys/{key_id}",
        headers=_SVC_HEADERS,
    )
    assert again.status_code == 404


def test_admin_revoke_api_key_cross_tenant_404(client: TestClient):
    kresp = client.post(
        "/api/v1/admin/tenants/default/api-keys",
        json={"scopes": ["inference"]},
        headers=_SVC_HEADERS,
    )
    key_id = kresp.json()["key_id"]
    client.post(
        "/api/v1/admin/tenants",
        json={"tenant_id": "other-tenant", "display_name": "Other"},
        headers=_SVC_HEADERS,
    )
    rev = client.delete(
        f"/api/v1/admin/tenants/other-tenant/api-keys/{key_id}",
        headers=_SVC_HEADERS,
    )
    assert rev.status_code == 404


def test_quota_priority_update(client: TestClient, admin_token: str):
    h = {"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"}
    resp = client.put(
        "/api/v1/tenants/default/quotas",
        json={"default_priority": 3, "allowed_modules": ["code", "agent"]},
        headers=h,
    )
    assert resp.status_code == 200, resp.text
    q = resp.json()
    assert q["default_priority"] == 3
    assert q["allowed_modules"] == ["code", "agent"]

    resp = client.get("/api/v1/tenants/default/quotas", headers=h)
    assert resp.status_code == 200
    assert resp.json()["default_priority"] == 3


def test_metrics_endpoint_has_prometheus(client: TestClient):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert "fusion_identity_auth_requests_total" in text
    assert "fusion_identity_tenant_active_concurrency" in text
    assert "fusion_identity_quota_remaining" in text
