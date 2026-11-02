from __future__ import annotations

from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


def _put(client: TestClient, app_id: str, name: str, value: str):
    return client.put(
        f"/api/v1/apps/{app_id}/credentials/{name}",
        json={"value": value},
        headers=_SVC_HEADERS,
    )


def _get(client: TestClient, app_id: str, name: str):
    return client.get(f"/api/v1/apps/{app_id}/credentials/{name}", headers=_SVC_HEADERS)


def test_put_then_get_roundtrip(client: TestClient):
    raw = "sk-fashn-live-abc123def456"
    resp = _put(client, "ai-trysuite", "fashn_api_key", raw)
    assert resp.status_code == 200, resp.text
    meta = resp.json()
    assert meta["app_id"] == "ai-trysuite"
    assert meta["name"] == "fashn_api_key"
    assert meta["fetch_count"] == 0
    assert "value" not in meta
    assert "secret_enc" not in meta

    got = _get(client, "ai-trysuite", "fashn_api_key")
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["value"] == raw
    assert body["fetch_count"] == 1
    assert body["last_fetched_at"] is not None


def test_at_rest_is_encrypted_not_plaintext(client: TestClient, store):
    raw = "sk-replicate-xyz789"
    _put(client, "ai-trysuite", "replicate_token", raw)
    rec = store._app_credentials[("ai-trysuite", "replicate_token")]
    assert raw not in rec["secret_enc"]
    assert rec["secret_enc"] != raw


def test_reput_overwrites_value_and_bumps_updated_at(client: TestClient):
    _put(client, "ai-trysuite", "kling_key", "old-value-000000000")
    first = _get(client, "ai-trysuite", "kling_key").json()
    resp = _put(client, "ai-trysuite", "kling_key", "new-value-111111111")
    assert resp.status_code == 200
    assert resp.json()["created_at"] == first["created_at"]
    second = _get(client, "ai-trysuite", "kling_key").json()
    assert second["value"] == "new-value-111111111"
    assert second["updated_at"] >= first["updated_at"]
    assert second["created_at"] == first["created_at"]


def test_get_unknown_credential_404(client: TestClient):
    assert _get(client, "ai-trysuite", "never_stored").status_code == 404


def test_missing_service_token_401(client: TestClient):
    resp = client.put(
        "/api/v1/apps/ai-trysuite/credentials/fashn_api_key",
        json={"value": "sk-whatever-123456"},
        headers={"X-Tenant-Id": "_system"},
    )
    assert resp.status_code == 401
    resp = client.get(
        "/api/v1/apps/ai-trysuite/credentials/fashn_api_key",
        headers={"X-Tenant-Id": "_system"},
    )
    assert resp.status_code == 401


def test_invalid_app_id_and_name_fail_closed(client: TestClient):
    assert _put(client, "Bad App", "name", "v").status_code == 422
    assert _put(client, "ai-trysuite", "bad name!", "v").status_code == 422
    assert _put(client, "ai-trysuite", "UPPER", "v").status_code == 422


def test_empty_value_rejected(client: TestClient):
    resp = client.put(
        "/api/v1/apps/ai-trysuite/credentials/empty_key",
        json={"value": ""},
        headers=_SVC_HEADERS,
    )
    assert resp.status_code == 422


def test_fetch_counter_increments_per_get(client: TestClient):
    _put(client, "ai-trysuite", "counter_key", "sk-counter-000001")
    for expected in (1, 2, 3):
        body = _get(client, "ai-trysuite", "counter_key").json()
        assert body["fetch_count"] == expected


def test_store_and_fetch_audited(client: TestClient, store):
    _put(client, "ai-trysuite", "audited_key", "sk-audit-000000001")
    _get(client, "ai-trysuite", "audited_key")
    records = [r for r in store._audit if r.get("action", "").startswith("app_credential.")]
    actions = sorted(r["action"] for r in records)
    assert actions == ["app_credential.fetched", "app_credential.stored"]
    assert all(r["tenant_id"] == "_system" for r in records)
    assert all(r["resource"] == "ai-trysuite/audited_key" for r in records)
    assert all("sk-audit" not in str(r.get("detail")) for r in records)
