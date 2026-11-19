from __future__ import annotations

import json
import logging

import pytest
from starlette.testclient import TestClient

from fusion_identity.ops_events import hash_tenant_id, hash_user_id
from tests.conftest import TEST_JWT_KEY, TEST_SERVICE_TOKEN

logger = logging.getLogger(__name__)

AUTH = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"}


class FakeEmitter:
    # Captures every emitted event for assertions; never drops.
    def __init__(self) -> None:
        self.events: list[dict] = []

    async def emit(self, event: dict) -> bool:
        self.events.append(event)
        return True

    def types(self) -> list[str]:
        return [e["event_type"] for e in self.events]


@pytest.fixture
def ops_client(app, client: TestClient) -> TestClient:
    # Attach a FakeEmitter to the live app state so every HTTP plane emits
    # into the capture list.
    app.state.ops_emitter = FakeEmitter()
    client.ops = app.state.ops_emitter  # type: ignore[attr-defined]
    return client


def _payload_strings(emitter: FakeEmitter) -> list[str]:
    return [json.dumps(e.get("payload", {})) for e in emitter.events]


def test_hash_ids_deterministic_and_prefixed():
    assert hash_user_id("usr_admin").startswith("u:")
    assert hash_tenant_id("default").startswith("t:")
    assert hash_user_id("usr_admin") == hash_user_id("usr_admin")
    assert hash_user_id("usr_admin") != hash_user_id("usr_other")
    assert len(hash_user_id("usr_admin")) == len("u:") + 16


def test_settings_default_true_and_roundtrip(ops_client: TestClient, admin_token: str):
    h = {"Authorization": f"Bearer {admin_token}"}
    r = ops_client.get("/api/v1/auth/settings", headers=h)
    assert r.status_code == 200
    assert r.json() == {"data_reflow_enabled": True}
    r = ops_client.put("/api/v1/auth/settings", json={"data_reflow_enabled": False}, headers=h)
    assert r.status_code == 200
    assert r.json() == {"data_reflow_enabled": False}
    r = ops_client.get("/api/v1/auth/settings", headers=h)
    assert r.json() == {"data_reflow_enabled": False}
    # Back to true (re-opt-in).
    r = ops_client.put("/api/v1/auth/settings", json={"data_reflow_enabled": True}, headers=h)
    assert r.json() == {"data_reflow_enabled": True}


def test_optout_event_only_on_false_transition(ops_client: TestClient, admin_token: str):
    h = {"Authorization": f"Bearer {admin_token}"}
    ops_client.put("/api/v1/auth/settings", json={"data_reflow_enabled": False}, headers=h)
    ops_client.put("/api/v1/auth/settings", json={"data_reflow_enabled": True}, headers=h)
    optouts = [e for e in ops_client.ops.events if e["event_type"] == "auth.data_reflow.optout"]
    # Exactly one optout event — the true->false transition. Re-opt-in emits none.
    assert len(optouts) == 1
    payload = optouts[0]["payload"]
    assert set(payload) == {"user_hash", "ts"}
    assert payload["user_hash"].startswith("u:")
    assert optouts[0]["tenant_hash"].startswith("t:")


def test_settings_requires_bearer(ops_client: TestClient):
    assert ops_client.get("/api/v1/auth/settings").status_code == 401
    assert (
        ops_client.put("/api/v1/auth/settings", json={"data_reflow_enabled": False}).status_code
        == 401
    )


def test_admin_data_reflow_flags_batch(ops_client: TestClient, admin_token: str):
    h = {"Authorization": f"Bearer {admin_token}"}
    ops_client.put("/api/v1/auth/settings", json={"data_reflow_enabled": False}, headers=h)
    login = ops_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    sub = login.json()["access_token"]
    from fusion_identity.ops_events import claims_from_token

    sub = claims_from_token(sub)["sub"]
    r = ops_client.post(
        "/api/v1/admin/data-reflow/flags",
        json={"user_ids": [sub, "usr_missing"]},
        headers=AUTH,
    )
    assert r.status_code == 200, r.text
    flags = r.json()["flags"]
    assert flags[sub] is False
    assert flags["usr_missing"] is True
    # Validation: empty list rejected.
    r = ops_client.post("/api/v1/admin/data-reflow/flags", json={"user_ids": []}, headers=AUTH)
    assert r.status_code == 422


def test_login_success_and_failure_emit(ops_client: TestClient):
    ok = ops_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert ok.status_code == 200
    bad = ops_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "WRONG", "tenant_id": "default"},
    )
    assert bad.status_code == 401
    types = ops_client.ops.types()
    assert "auth.login.success" in types
    assert "auth.login.failure" in types
    success = next(e for e in ops_client.ops.events if e["event_type"] == "auth.login.success")
    assert set(success["payload"]) == {"user_hash"}
    assert success["status"] == 200
    assert success["latency_ms"] >= 0
    failure = next(e for e in ops_client.ops.events if e["event_type"] == "auth.login.failure")
    # No user id on the failure path — no account-existence oracle.
    assert set(failure["payload"]) == {"reason"}


def test_refresh_emits_token_issued(ops_client: TestClient, admin_token: str):
    login = ops_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    refresh = login.json()["refresh_token"]
    r = ops_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    kinds = [
        e["payload"].get("kind")
        for e in ops_client.ops.events
        if e["event_type"] == "auth.token.issued"
    ]
    assert "refresh" in kinds


def test_payload_hygiene_no_raw_secrets(ops_client: TestClient, admin_token: str):
    # Hard rule: raw emails / usernames / JWTs / passwords never reach ops payloads.
    raw_email = "admin@example.com"
    ops_client.put(
        "/api/v1/auth/settings",
        json={"data_reflow_enabled": False},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    ops_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    ops_client.post(
        "/api/v1/auth/login",
        json={"username": "nobody", "password": "bad", "tenant_id": "default"},
    )
    ops_client.post("/api/v1/auth/password/forgot", json={"email": raw_email})
    blob = " ".join(_payload_strings(ops_client.ops))
    for banned in (raw_email, "adminpass", "usr_admin", "admin"):
        assert banned not in blob, f"raw secret leaked into ops payload: {banned}"
    # JWT fragments never appear either.
    for e in ops_client.ops.events:
        assert "access_token" not in json.dumps(e.get("payload", {}))


def test_no_emitter_login_still_works(client: TestClient):
    # ops plane off (default): every emit is a no-op, auth unaffected.
    r = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert r.status_code == 200
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    r = client.get("/api/v1/auth/settings", headers=h)
    assert r.json() == {"data_reflow_enabled": True}


def test_emitter_failure_never_breaks_auth(client: TestClient):
    class BrokenEmitter:
        async def emit(self, event: dict) -> bool:
            raise RuntimeError("ops db down")

    client.app.state.ops_emitter = BrokenEmitter()
    r = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert r.status_code == 200


def test_retention_sweep_emits_tenant_stats(store, settings):
    import asyncio

    from fusion_identity.retention import RetentionWorker

    asyncio.run(store.connect())

    class FakeApp:
        pass

    emitter = FakeEmitter()
    worker = RetentionWorker(store, emitter=emitter)
    stats = asyncio.run(worker.sweep_once())
    assert stats == {"purged": 0, "pruned_tokens": 0, "pruned_audit": 0}
    assert emitter.types() == ["auth.tenant.stats"]
    snap = emitter.events[0]["payload"]
    assert set(snap) == {"tenants", "users"}
    asyncio.run(worker.stop())
    asyncio.run(store.close())


def test_jwt_key_not_in_events(ops_client: TestClient):
    ops_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    blob = json.dumps(ops_client.ops.events)
    assert TEST_JWT_KEY not in blob
