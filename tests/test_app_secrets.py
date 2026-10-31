from __future__ import annotations

import time
from typing import Any

import pytest
from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


def _issue(client: TestClient, app_id: str, body: dict[str, Any] | None = None):
    return client.post(f"/api/v1/apps/{app_id}/secrets", json=body, headers=_SVC_HEADERS)


def _rotate(client: TestClient, app_id: str, body: dict[str, Any] | None = None):
    return client.post(f"/api/v1/apps/{app_id}/secrets/rotate", json=body, headers=_SVC_HEADERS)


def _list(client: TestClient, app_id: str):
    return client.get(f"/api/v1/apps/{app_id}/secrets", headers=_SVC_HEADERS)


def test_issue_returns_secret_once_and_list_hides_plaintext(client: TestClient):
    resp = _issue(client, "ai-assistant-agent")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["app_id"] == "ai-assistant-agent"
    assert body["version"] == 1
    assert body["status"] == "current"
    assert body["secret"].startswith("fms_")
    assert body["previous_version"] is None

    listed = _list(client, "ai-assistant-agent")
    assert listed.status_code == 200
    versions = listed.json()
    assert len(versions) == 1
    assert versions[0]["version"] == 1
    assert versions[0]["status"] == "current"
    assert "secret" not in versions[0]
    assert "secret_hash" not in versions[0]
    assert versions[0]["prefix"].endswith("****")


def test_issue_twice_conflicts_until_rotated(client: TestClient):
    assert _issue(client, "cv-app").status_code == 201
    dup = _issue(client, "cv-app")
    assert dup.status_code == 409
    assert "rotate" in dup.json()["detail"]


def test_rotate_demotes_previous_to_grace(client: TestClient):
    assert _issue(client, "rot-app").status_code == 201
    resp = _rotate(client, "rot-app", {"grace_seconds": 3600})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["version"] == 2
    assert body["previous_version"]["version"] == 1
    assert body["previous_version"]["status"] == "grace"
    assert body["previous_version"]["grace_until"] > time.time()

    versions = _list(client, "rot-app").json()
    assert [v["version"] for v in versions] == [2, 1]
    assert versions[0]["status"] == "current"
    assert versions[1]["status"] == "grace"
    assert versions[1]["grace_until"] is not None


def test_rotate_unknown_app_404(client: TestClient):
    assert _rotate(client, "ghost-app").status_code == 404


def test_grace_expiry_reads_back_expired(client: TestClient):
    assert _issue(client, "exp-app").status_code == 201
    assert _rotate(client, "exp-app", {"grace_seconds": 0}).status_code == 201
    versions = _list(client, "exp-app").json()
    assert versions[0]["status"] == "current"
    assert versions[1]["status"] == "expired"


def test_service_token_required(client: TestClient):
    no_auth = client.post("/api/v1/apps/x-app/secrets")
    assert no_auth.status_code == 401
    bad = client.post(
        "/api/v1/apps/x-app/secrets",
        headers={"Authorization": "Bearer wrong-token", "X-Tenant-Id": "_system"},
    )
    assert bad.status_code == 401
    listed = client.get("/api/v1/apps/x-app/secrets")
    assert listed.status_code == 401


def test_app_id_validated_fail_closed(client: TestClient):
    for bad_id in ("Upper", "-lead", "a" * 65, "sp ace"):
        resp = client.post(f"/api/v1/apps/{bad_id}/secrets", headers=_SVC_HEADERS)
        assert resp.status_code in (401, 422), f"{bad_id!r} -> {resp.status_code}"
    # Empty app_id and slash-containing ids match no route — 404 is equally
    # fail-closed (nothing is created or revealed).
    for path in ("/api/v1/apps//secrets", "/api/v1/apps/app/x/secrets"):
        assert client.post(path, headers=_SVC_HEADERS).status_code == 404


def test_versions_increment_across_rotations(client: TestClient):
    _issue(client, "inc-app")
    for expected in (2, 3, 4):
        resp = _rotate(client, "inc-app", {"grace_seconds": 60})
        assert resp.status_code == 201
        assert resp.json()["version"] == expected


def test_audit_events_recorded(client: TestClient, store):
    assert _issue(client, "aud-app").status_code == 201
    assert _rotate(client, "aud-app", {"grace_seconds": 60}).status_code == 201
    records = [r for r in store._audit if r.get("action", "").startswith("app_secret.")]
    actions = sorted(r["action"] for r in records)
    assert actions == ["app_secret.issued", "app_secret.rotated"]
    assert all(r["tenant_id"] == "_system" for r in records)
    assert all(r["resource"] == "aud-app" for r in records)


@pytest.mark.parametrize(
    "grace_body",
    [{"grace_seconds": -1}, {"grace_seconds": 10**9}],
)
def test_grace_seconds_bounds_rejected(client: TestClient, grace_body):
    resp = _issue(client, "bound-app", grace_body)
    assert resp.status_code == 422
