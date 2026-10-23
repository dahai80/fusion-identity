from __future__ import annotations

import json
from typing import Any

import pytest
from starlette.testclient import TestClient

from fusion_identity.events import sign_payload
from fusion_identity.store import InMemoryStore
from tests.conftest import TEST_SERVICE_TOKEN

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


def _provision(
    client: TestClient,
    body: dict[str, Any],
    idem_key: str | None = None,
) -> Any:
    headers = dict(_SVC_HEADERS)
    if idem_key:
        headers["Idempotency-Key"] = idem_key
    return client.post("/api/v1/admin/tenants/provision", json=body, headers=headers)


def test_provision_one_shot_creates_tenant_quota_admin_and_key(client: TestClient):
    resp = _provision(
        client,
        {
            "tenant_id": "cva",
            "display_name": "CharacterVoiceAgent",
            "plan": "pro",
            "seed_admin": {"username": "cva_admin", "password": "super-secret-pass-123"},
            "api_key": {"scopes": ["inference"]},
            "quotas": {"concurrent": 8},
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["tenant"]["tenant_id"] == "cva"
    assert body["tenant"]["plan"] == "pro"
    # M-C: plan template applied, per-tenant override wins.
    assert body["quota"]["concurrent"] == 8
    assert body["quota"]["tpm"] == 1000000
    assert body["admin"]["username"] == "cva_admin"
    assert body["admin"]["must_change_password"] is False
    assert body["api_key"]["raw_key"].startswith("fmu_")
    assert "key_hash" not in body["api_key"]

    # seed admin can actually log in
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "cva_admin", "password": "super-secret-pass-123", "tenant_id": "cva"},
    )
    assert login.status_code == 200, login.text

    # lifecycle events in the outbox
    events = client.get("/api/v1/admin/events", headers=_SVC_HEADERS).json()
    types = [e["event_type"] for e in events["events"]]
    assert "tenant.created" in types
    assert "apikey.created" in types


def test_provision_generates_password_when_omitted(client: TestClient):
    resp = _provision(
        client,
        {
            "tenant_id": "genpw",
            "display_name": "GenPW",
            "plan": "free",
            "seed_admin": {"username": "gen_admin"},
        },
    )
    assert resp.status_code == 201, resp.text
    admin = resp.json()["admin"]
    assert admin["initial_password"]
    assert admin["must_change_password"] is True
    # generated password works
    login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "gen_admin",
            "password": admin["initial_password"],
            "tenant_id": "genpw",
        },
    )
    assert login.status_code == 200, login.text


def test_provision_idempotent_replay_creates_nothing_new(client: TestClient):
    body = {
        "tenant_id": "idem",
        "display_name": "Idem",
        "plan": "starter",
        "seed_admin": {"username": "idem_admin", "password": "super-secret-pass-123"},
        "api_key": {"scopes": []},
    }
    first = _provision(client, body, idem_key="key-001")
    assert first.status_code == 201, first.text
    first_body = first.json()

    second = _provision(client, body, idem_key="key-001")
    assert second.status_code == 201, second.text
    second_body = second.json()
    assert second_body["idempotent_replay"] is True
    assert first_body["idempotent_replay"] is False
    assert second_body["tenant"]["tenant_id"] == first_body["tenant"]["tenant_id"]
    assert second_body["api_key"]["raw_key"] == first_body["api_key"]["raw_key"]

    # no duplicate tenant was created
    tenants = client.get("/api/v1/admin/tenants", headers=_SVC_HEADERS).json()
    assert [t["tenant_id"] for t in tenants].count("idem") == 1


def test_provision_conflict_username_prechecked_before_tenant(client: TestClient):
    # bootstrap created global user "admin" — provisioning a tenant with that
    # seed username must fail BEFORE creating the tenant (no orphan tenant).
    resp = _provision(
        client,
        {
            "tenant_id": "orphan",
            "display_name": "Orphan",
            "plan": "free",
            "seed_admin": {"username": "admin"},
        },
    )
    assert resp.status_code == 409, resp.text
    tenants = client.get("/api/v1/admin/tenants", headers=_SVC_HEADERS).json()
    assert "orphan" not in [t["tenant_id"] for t in tenants]


def test_provision_duplicate_tenant_id_409(client: TestClient):
    resp = _provision(client, {"tenant_id": "default", "display_name": "Dup", "plan": "free"})
    assert resp.status_code == 409


def test_plan_template_admin_managed(client: TestClient):
    resp = client.get("/api/v1/admin/plan-templates", headers=_SVC_HEADERS)
    assert resp.status_code == 200
    plans = {t["plan"] for t in resp.json()}
    assert {"free", "starter", "standard", "pro", "enterprise"} <= plans

    resp = client.put(
        "/api/v1/admin/plan-templates/saas",
        json={"quota": {"rpm": 100, "tpm": 250000, "concurrent": 10}},
        headers=_SVC_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["quota"]["rpm"] == 100

    resp = _provision(client, {"tenant_id": "saastnt", "display_name": "SaaS", "plan": "saas"})
    assert resp.status_code == 201, resp.text
    assert resp.json()["quota"]["rpm"] == 100
    assert resp.json()["quota"]["tpm"] == 250000

    resp = client.get("/api/v1/admin/plan-templates/nope", headers=_SVC_HEADERS)
    assert resp.status_code == 404


def test_events_polling_cursor(client: TestClient):
    resp = _provision(client, {"tenant_id": "evt", "display_name": "Evt", "plan": "free"})
    assert resp.status_code == 201
    first = client.get("/api/v1/admin/events", headers=_SVC_HEADERS).json()
    assert first["events"], "expected events in outbox"
    cursor = first["next_cursor"]
    second = client.get(
        "/api/v1/admin/events", params={"cursor": cursor}, headers=_SVC_HEADERS
    ).json()
    created_after = [e for e in second["events"] if e["tenant_id"] == "evt"]
    assert created_after == [], "cursor must exclude already-seen events"


def test_lifecycle_events_from_existing_routes(client: TestClient, admin_token: str):
    headers = {"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"}

    # quota change via PUT quotas
    resp = client.put(
        "/api/v1/tenants/default/quotas",
        json={"rpm": 77},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    # api key create + revoke
    resp = client.post(
        "/api/v1/tenants/default/api-keys",
        json={"scopes": ["inference"]},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    key_id = resp.json()["key_id"]
    resp = client.delete(f"/api/v1/tenants/default/api-keys/{key_id}", headers=headers)
    assert resp.status_code == 200, resp.text

    # status change via PATCH /tenants/{id} — last, a disabled tenant rejects
    # further tenant-scoped calls by design (fail-closed)
    resp = client.patch(
        "/api/v1/tenants/default",
        json={"status": "disabled"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    events = client.get("/api/v1/admin/events", headers=_SVC_HEADERS).json()["events"]
    types = [e["event_type"] for e in events if e["tenant_id"] == "default"]
    assert "tenant.status_changed" in types
    assert "tenant.quota_changed" in types
    assert "apikey.created" in types
    assert "apikey.revoked" in types


def test_provision_hook_dispatched(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}

    async def fake_hook(url: str, secret: str, event: str, data: dict[str, Any]) -> dict[str, Any]:
        captured["url"] = url
        captured["event"] = event
        captured["data"] = data
        return {"status": "delivered", "http_status": 200}

    monkeypatch.setattr("fusion_identity.routes.provisioning.dispatch_hook", fake_hook)
    resp = _provision(
        client,
        {
            "tenant_id": "hooked",
            "display_name": "Hooked",
            "plan": "free",
            "hook_url": "http://127.0.0.1:19999/register",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["hook"]["status"] == "delivered"
    assert captured["url"] == "http://127.0.0.1:19999/register"
    assert captured["event"] == "provision.completed"
    assert captured["data"]["tenant"]["tenant_id"] == "hooked"


def test_sign_payload_deterministic_hmac():
    body = b'{"event": "tenant.created"}'
    sig = sign_payload("secret-material", body)
    assert sig == sign_payload("secret-material", body)
    assert sig != sign_payload("other-secret", body)
    assert len(sig) == 64


@pytest.mark.asyncio
async def test_webhook_worker_delivery_and_dead_letter():
    import httpx

    from fusion_identity.events import WebhookWorker

    store = InMemoryStore()
    await store.append_event("tenant.created", "default", {"plan": "free"})

    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        # first two attempts fail, third succeeds
        if len(calls) < 3:
            return httpx.Response(500)
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    worker = WebhookWorker(
        store,
        "http://webhook.test/hook",
        "whsec",
        tick_seconds=0.01,
        max_attempts=3,
        http_client=httpx.AsyncClient(transport=transport),
    )
    for _ in range(3):
        await worker._tick()
    events = await store.list_events()
    assert events[0]["status"] == "delivered"
    assert events[0]["attempts"] == 3
    assert len(calls) == 3
    # signature header present and valid
    sig = calls[0].headers["X-Fusion-Signature"]
    assert sig.startswith("sha256=")
    assert sig == "sha256=" + sign_payload("whsec", calls[0].read())
    await worker._http_client.aclose()


@pytest.mark.asyncio
async def test_webhook_worker_dead_letter():
    import httpx

    from fusion_identity.events import WebhookWorker

    store = InMemoryStore()
    await store.append_event("tenant.created", "default", {})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    worker = WebhookWorker(
        store,
        "http://webhook.test/hook",
        "whsec",
        tick_seconds=0.01,
        max_attempts=2,
        http_client=client,
    )
    await worker._tick()
    await worker._tick()
    events = await store.list_events()
    assert events[0]["status"] == "dead"
    assert events[0]["attempts"] == 2
    await client.aclose()


def test_webhook_config_requires_secret():
    import os

    from fusion_identity.config import ConfigError, load_settings

    saved = {
        k: os.environ.pop(k, None)
        for k in (
            "FUSION_IDENTITY_JWT_KEY",
            "FUSION_IDENTITY_SERVICE_TOKEN",
            "FUSION_IDENTITY_KEK",
            "FUSION_IDENTITY_WEBHOOK_URL",
            "FUSION_IDENTITY_WEBHOOK_SECRET",
        )
    }
    try:
        os.environ["FUSION_IDENTITY_JWT_KEY"] = "x" * 40
        os.environ["FUSION_IDENTITY_SERVICE_TOKEN"] = "y" * 30
        os.environ["FUSION_IDENTITY_KEK"] = "z" * 40
        os.environ["FUSION_IDENTITY_WEBHOOK_URL"] = "http://127.0.0.1:1/hook"
        with pytest.raises(ConfigError):
            load_settings()
        os.environ["FUSION_IDENTITY_WEBHOOK_SECRET"] = "s" * 30
        settings = load_settings()
        assert settings.webhook_url == "http://127.0.0.1:1/hook"
        assert settings.webhook_secret == "s" * 30
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_provision_requires_service_token(client: TestClient):
    resp = client.post(
        "/api/v1/admin/tenants/provision",
        json={"display_name": "Nope", "plan": "free"},
        headers={"X-Tenant-Id": "_system"},
    )
    assert resp.status_code == 401


def test_provision_raw_key_not_in_events(client: TestClient):
    resp = _provision(
        client,
        {
            "tenant_id": "nokey",
            "display_name": "NoKey",
            "plan": "free",
            "api_key": {"scopes": []},
        },
    )
    assert resp.status_code == 201
    raw = resp.json()["api_key"]["raw_key"]
    events = client.get("/api/v1/admin/events", headers=_SVC_HEADERS).json()
    blob = json.dumps(events)
    assert raw not in blob
