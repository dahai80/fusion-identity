from __future__ import annotations

import logging

from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN, _admin_token

logger = logging.getLogger(__name__)

SVC = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "default"}


def _admin_headers(client: TestClient) -> dict:
    return {"Authorization": f"Bearer {_admin_token(client)}", "X-Tenant-Id": "default"}


def _create_dept(client: TestClient, headers: dict, name: str = "eng", tools: list | None = None):
    resp = client.post(
        "/api/v1/tenants/default/departments",
        json={"name": name, "tool_allowlist": tools or ["tool.a", "tool.b"]},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_department_crud_roundtrip(client: TestClient) -> None:
    headers = _admin_headers(client)
    dept = _create_dept(client, headers, name="research", tools=["tool.x"])
    assert dept["name"] == "research"
    assert dept["tool_allowlist"] == ["tool.x"]
    assert dept["dept_id"].startswith("dept_")

    listed = client.get("/api/v1/tenants/default/departments", headers=headers).json()
    assert any(d["dept_id"] == dept["dept_id"] for d in listed)

    got = client.get(
        f"/api/v1/tenants/default/departments/{dept['dept_id']}", headers=headers
    ).json()
    assert got["name"] == "research"

    patched = client.patch(
        f"/api/v1/tenants/default/departments/{dept['dept_id']}",
        json={"tool_allowlist": ["tool.y"], "name": "research-2"},
        headers=headers,
    )
    assert patched.status_code == 200
    assert patched.json()["tool_allowlist"] == ["tool.y"]

    deleted = client.delete(
        f"/api/v1/tenants/default/departments/{dept['dept_id']}", headers=headers
    )
    assert deleted.status_code == 200
    gone = client.get(f"/api/v1/tenants/default/departments/{dept['dept_id']}", headers=headers)
    assert gone.status_code == 404


def test_department_cross_tenant_denied(client: TestClient) -> None:
    headers = _admin_headers(client)
    _create_dept(client, headers)
    # admin of default cannot read tenant 'other' departments (red line 2)
    resp = client.get("/api/v1/tenants/other/departments", headers=headers)
    assert resp.status_code == 403


def test_department_requires_admin(client: TestClient) -> None:
    resp = client.get("/api/v1/tenants/default/departments")
    assert resp.status_code == 401


def test_usage_summary_aggregates(client: TestClient) -> None:
    headers = _admin_headers(client)
    for i in range(3):
        resp = client.post(
            "/api/v1/tenants/default/usage",
            json={"user_id": "usr_admin", "metric": "tokens", "value": 100 + i, "source": "grpc"},
            headers=SVC,
        )
        assert resp.status_code == 200, resp.text
    client.post(
        "/api/v1/tenants/default/usage",
        json={"user_id": "usr_admin", "metric": "runs", "value": 2, "source": "http"},
        headers=SVC,
    )
    resp = client.get("/api/v1/tenants/default/usage/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == "default"
    assert body["events"] >= 4
    assert body["totals"]["tokens"] >= 303
    assert body["totals"]["runs"] >= 2
    assert body["by_source"]["grpc"] >= 303
    assert body["by_source"]["http"] >= 2
    assert "unspecified" in body["by_model"]


def test_audit_event_ingest_and_otlp_export(client: TestClient) -> None:
    headers = _admin_headers(client)
    resp = client.post(
        "/api/v1/tenants/default/audit/events",
        json={
            "action": "tool.approval",
            "resource": "tool:x",
            "user_id": "usr_admin",
            "severity": "WARN",
            "detail": {"decision": "allow"},
        },
        headers=SVC,
    )
    assert resp.status_code == 201, resp.text
    rec = resp.json()
    assert rec["action"] == "external.tool.approval"
    assert rec["chain_hash"]

    otlp = client.get("/api/v1/tenants/default/audit/otlp?limit=100", headers=headers)
    assert otlp.status_code == 200, otlp.text
    payload = otlp.json()
    rl = payload["resourceLogs"][0]
    assert rl["resource"]["attributes"][0]["key"] == "service.name"
    records = rl["scopeLogs"][0]["logRecords"]
    assert records, "expected non-empty logRecords"
    actions = [r["body"]["stringValue"] for r in records]
    assert "external.tool.approval" in actions
    target = next(r for r in records if r["body"]["stringValue"] == "external.tool.approval")
    assert target["severityText"] == "WARN"
    keys = {a["key"] for a in target["attributes"]}
    assert "tenant.id" in keys and "audit.detail" in keys


def test_otlp_export_with_service_token(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/tenants/default/audit/otlp", headers=SVC | {"X-Tenant-Id": "default"}
    )
    assert resp.status_code == 200
    assert "resourceLogs" in resp.json()


def test_otlp_export_requires_auth(client: TestClient) -> None:
    resp = client.get("/api/v1/tenants/default/audit/otlp")
    assert resp.status_code == 401


def test_audit_chain_still_valid_after_ingest(client: TestClient) -> None:
    headers = _admin_headers(client)
    client.post(
        "/api/v1/tenants/default/audit/events",
        json={"action": "run.complete", "detail": {}},
        headers=SVC,
    )
    resp = client.get("/api/v1/tenants/default/audit/verify", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["valid"] is True
