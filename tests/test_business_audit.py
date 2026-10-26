from __future__ import annotations

import time

from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN

SVC = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "default"}

_PATH = "/api/v1/tenants/default/audit"


def _event(trace_id: str, action: str = "ai.invoke", **overrides) -> dict:
    body = {
        "actor": "user:u1",
        "action": action,
        "object_id": "exam:run-1",
        "trace_id": trace_id,
        "timestamp": time.time(),
        "payload": {"model": "whisper", "score": 0.92},
    }
    body.update(overrides)
    return body


def test_business_event_append_and_chain(client: TestClient) -> None:
    resp = client.post(f"{_PATH}/business-events", json=_event("tr-001"), headers=SVC)
    assert resp.status_code == 201, resp.text
    rec = resp.json()
    assert rec["action"] == "external.ai.invoke"
    assert rec["chain_hash"] and rec["seq"]
    assert rec["trace_id"] == "tr-001"
    assert rec["ts"]
    # chain integrity intact after external append
    from tests.test_admin_contract import _admin_headers

    v = client.get(f"{_PATH}/verify", headers=_admin_headers(client))
    assert v.status_code == 200
    assert v.json()["valid"] is True


def test_business_event_required_fields(client: TestClient) -> None:
    for missing in ("actor", "action", "object_id", "trace_id", "timestamp"):
        body = _event("tr-req")
        body.pop(missing)
        resp = client.post(f"{_PATH}/business-events", json=body, headers=SVC)
        assert resp.status_code == 422, f"{missing} should be required: {resp.text}"
    # timestamp sanity: far-future rejected, negative rejected
    for bad_ts in (time.time() + 3600, -1):
        resp = client.post(
            f"{_PATH}/business-events", json=_event("tr-bad", timestamp=bad_ts), headers=SVC
        )
        assert resp.status_code == 422, resp.text


def test_business_event_unknown_tenant_404(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/tenants/nope/audit/business-events", json=_event("tr-404"), headers=SVC
    )
    assert resp.status_code == 404


def test_business_event_requires_service_token(client: TestClient, admin_token: str) -> None:
    # a tenant admin JWT is NOT a service credential — append must refuse
    resp = client.post(
        f"{_PATH}/business-events",
        json=_event("tr-nope"),
        headers={"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"},
    )
    assert resp.status_code == 401


def test_business_event_query_filters(client: TestClient, admin_token: str) -> None:
    client.post(f"{_PATH}/business-events", json=_event("tr-a", action="ai.invoke"), headers=SVC)
    client.post(
        f"{_PATH}/business-events", json=_event("tr-b", action="expert.approve"), headers=SVC
    )
    client.post(
        f"{_PATH}/business-events",
        json=_event("tr-b", action="score.override", actor="user:u2"),
        headers=SVC,
    )
    h = {"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"}

    resp = client.get(f"{_PATH}/business-events", params={"trace_id": "tr-a"}, headers=h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 1 and body["truncated"] is False
    assert body["events"][0]["detail"]["trace_id"] == "tr-a"

    resp = client.get(f"{_PATH}/business-events", params={"trace_id": "tr-b"}, headers=h)
    assert resp.json()["count"] == 2

    resp = client.get(f"{_PATH}/business-events", params={"actor": "user:u2"}, headers=h)
    body = resp.json()
    assert body["count"] == 1
    assert body["events"][0]["action"] == "external.score.override"

    resp = client.get(
        f"{_PATH}/business-events",
        params={"action": "expert.approve", "object_id": "exam:run-1"},
        headers=h,
    )
    assert resp.json()["count"] == 1

    # internal audit rows (non-business) never leak into business queries
    resp = client.get(f"{_PATH}/business-events", headers=h)
    actions = {e["action"] for e in resp.json()["events"]}
    assert all(a.startswith("external.") for a in actions)


def test_business_event_query_permission(client: TestClient) -> None:
    # no token
    assert client.get(f"{_PATH}/business-events").status_code == 401
    # viewer role has no audit read
    from tests.test_rbac_matrix import _make_role_user

    viewer = _make_role_user(client, "biz_viewer", "viewer")
    assert client.get(f"{_PATH}/business-events", headers=viewer).status_code == 403


def test_compliance_export(client: TestClient, admin_token: str) -> None:
    client.post(f"{_PATH}/business-events", json=_event("tr-exp"), headers=SVC)
    h = {"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"}
    resp = client.get(f"{_PATH}/export", headers=h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == "default"
    assert body["chain"]["valid"] is True
    assert body["count"] >= 1
    actions = {e["action"] for e in body["events"]}
    assert "external.ai.invoke" in actions
    # service token can pull the export too (compliance collector)
    resp = client.get(f"{_PATH}/export", headers=SVC)
    assert resp.status_code == 200
    assert resp.json()["chain"]["valid"] is True


def test_export_requires_auth(client: TestClient) -> None:
    assert client.get(f"{_PATH}/export").status_code == 401
