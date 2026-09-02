from __future__ import annotations

from starlette.testclient import TestClient


def test_metrics_exposes_gauges(client: TestClient):
    resp = client.get("/metrics")
    assert resp.status_code == 200, resp.text
    assert "text/plain" in resp.headers.get("content-type", "")
    body = resp.text
    assert "fusion_identity_tenants" in body
    assert "fusion_identity_users" in body
    assert "fusion_identity_uptime_seconds" in body
    assert "fusion_identity_python_info" in body


def test_metrics_no_auth_required(client: TestClient):
    resp = client.get("/metrics", headers={})
    assert resp.status_code == 200, resp.text


def test_metrics_counts_reflect_state(client: TestClient):
    token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]
    client.post(
        "/api/v1/tenants/default/members",
        json={"username": "m1", "password": "pw12345678", "role": "member"},
        headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": "default"},
    )
    resp = client.get("/metrics")
    body = resp.text
    members_line = [ln for ln in body.splitlines() if ln.startswith("fusion_identity_members ")]
    assert members_line, body
    assert int(members_line[0].split()[1]) >= 2
