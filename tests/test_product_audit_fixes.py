from __future__ import annotations

import logging

import jwt
import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.config import Settings
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

TEST_JWT_KEY = "test-signing-key-please-not-prod"
TEST_SERVICE_TOKEN = "test-service-token"
TEST_KEK = "test-kek-material-distinct-from-jwt-key"

_SVC_HEADERS = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


def _settings(**overrides) -> Settings:
    base = dict(
        host="127.0.0.1",
        port=11470,
        database_url="postgresql://127.0.0.1:5432/fusion_tenant",
        use_pgstore=False,
        jwt_signing_key=TEST_JWT_KEY,
        jwt_issuer="fusion-identity",
        jwt_audience="fusion-cluster",
        jwt_ttl_seconds=3600,
        refresh_ttl_seconds=86400,
        service_token=TEST_SERVICE_TOKEN,
        bootstrap_admin_user="admin",
        bootstrap_admin_pass="adminpass",
        bootstrap_tenants=None,
        log_level="WARNING",
        log_json=False,
        login_rate_limit=0,
        login_rate_window=60,
        jwt_algorithm="HS256",
        jwt_private_key_pem=None,
        jwt_public_keys=None,
        kek=TEST_KEK,
        mfa_enforce_admin=False,
        redis_url="",
        grpc_port=0,
        lease_ttl_seconds=120,
        trusted_proxies=frozenset(),
        jwt_keyring_path="",
        db_pool_max=8,
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def client() -> TestClient:
    settings = _settings()
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        yield c


async def _scim_create_user(client: TestClient, tenant: str, username: str, display: str) -> dict:
    resp = client.post(
        f"/scim/v2/Users?tenantId={tenant}",
        headers=_SVC_HEADERS,
        json={"userName": username, "displayName": display, "active": True},
    )
    assert resp.status_code in (200, 201), resp.text
    return resp.json()


def test_p0_1_scim_display_name_persists_via_update_user(client: TestClient):
    # P0-1: a SCIM displayName written at create must survive a PATCH and a
    # re-read. Before the fix PgStore.update_user omitted display_name from its
    # allowlist, so the value silently vanished on Postgres (InMemory masked it).
    created = client.post(
        "/scim/v2/Users?tenantId=default",
        headers=_SVC_HEADERS,
        json={"userName": "alice", "displayName": "Alice Wong", "active": True},
    )
    assert created.status_code in (200, 201), created.text
    uid = created.json()["id"]
    assert created.json()["displayName"] == "Alice Wong"
    patch = client.patch(
        f"/scim/v2/Users/{uid}?tenantId=default",
        headers=_SVC_HEADERS,
        json={
            "Operations": [
                {"op": "replace", "path": "displayName", "value": "Alice L. Wong"},
                {"op": "replace", "path": "active", "value": True},
            ]
        },
    )
    assert patch.status_code == 200, patch.text
    assert patch.json()["displayName"] == "Alice L. Wong"
    got = client.get(f"/scim/v2/Users/{uid}?tenantId=default", headers=_SVC_HEADERS)
    assert got.status_code == 200, got.text
    assert got.json()["displayName"] == "Alice L. Wong"


def test_p1_1_scim_unsupported_filter_returns_400(client: TestClient):
    # P1-1: an unsupported SCIM filter must fail-closed with 400, not silently
    # return all resources (which leaks the full member list).
    resp = client.get(
        "/scim/v2/Users?tenantId=default&filter=userName+co+%22ali%22",
        headers=_SVC_HEADERS,
    )
    assert resp.status_code == 400, resp.text


def test_p1_2_scim_patch_operations_array_disable(client: TestClient):
    # P1-2: RFC 7644 PATCH uses an Operations array. Active->false must disable.
    created = client.post(
        "/scim/v2/Users?tenantId=default",
        headers=_SVC_HEADERS,
        json={"userName": "bob", "displayName": "Bob", "active": True},
    )
    uid = created.json()["id"]
    patch = client.patch(
        f"/scim/v2/Users/{uid}?tenantId=default",
        headers=_SVC_HEADERS,
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
    )
    assert patch.status_code == 200, patch.text
    assert patch.json()["active"] is False


def test_p1_3_ready_healthy_returns_200(client: TestClient):
    # P1-3: /ready probes the store; a healthy InMemoryStore returns 200.
    resp = client.get("/ready")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "ready"
    assert resp.json()["checks"]["store"] == "ok"


def test_p1_3_ready_broken_store_returns_503():
    # P1-3: a store whose stats() raises must surface 503 so the orchestrator
    # stops routing traffic (the static /health would have stayed 200).
    settings = _settings()
    store = InMemoryStore()

    async def boom():
        raise RuntimeError("db down")

    store.stats = boom  # type: ignore[method-assign]
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        resp = c.get("/ready")
    assert resp.status_code == 503, resp.text
    assert resp.json()["status"] == "unready"


def test_p1_6_security_headers_present(client: TestClient):
    # P1-6: the ASGI security-headers middleware must set defensive headers on
    # every response.
    resp = client.get("/ready")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "strict-transport-security" in resp.headers
    assert resp.headers.get("referrer-policy") == "no-referrer"


def test_p2_4_alg_none_token_rejected(client: TestClient):
    # P2-4: an alg=none token (the classic JWT bypass) must be rejected at
    # verify, not accepted as valid.
    token = jwt.encode(
        {"sub": "admin", "tid": "default", "role": "tenant_admin", "type": "access"},
        key="",
        algorithm="none",
    )
    resp = client.get(
        "/api/v1/auth/verify",
        params={"token": token},
        headers=_SVC_HEADERS,
    )
    assert resp.status_code in (400, 401), resp.text


def test_p2_5_per_username_rate_limit_denies(client: TestClient):
    # P2-5: a tight per-username bucket must throttle repeated bad logins for
    # the SAME username even from one IP, where the IP bucket alone would not.
    settings = _settings(login_rate_limit=2, login_rate_window=60)
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        bodies = [
            {"username": "admin", "password": "wrong", "tenant_id": "default"}
            for _ in range(5)
        ]
        statuses = []
        for b in bodies:
            r = c.post("/api/v1/auth/login", json=b)
            statuses.append(r.status_code)
    assert 429 in statuses, statuses


def test_p2_10_tenant_update_conflict_returns_409(client: TestClient):
    # P2-10: a store-level conflict on update_tenant must surface as 409, not
    # a raw 500. We force StoreConflict via a monkeypatched store method.
    from fusion_identity.store import StoreConflict

    settings = _settings()
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)

    original = store.update_tenant

    async def conflict(*a, **kw):
        raise StoreConflict("display_name collision")

    store.update_tenant = conflict  # type: ignore[method-assign]
    token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]
    try:
        with TestClient(app) as c:
            resp = c.patch(
                "/api/v1/tenants/default",
                headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": "default"},
                json={"display_name": "new"},
            )
        assert resp.status_code == 409, resp.text
    finally:
        store.update_tenant = original  # type: ignore[method-assign]


def test_p2_11_api_key_revoke_cache_fail_returns_500():
    # P2-11: if the cache invalidation on api-key revoke fails, the route must
    # fail-closed (500), not log-and-continue (which would leave a stale cached
    # key usable). We simulate a broken cache object injected post-startup.
    settings = _settings()
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)

    class BrokenCache:
        async def invalidate_api_key_by_hash(self, *a, **kw):
            raise RuntimeError("redis evicted")

    with TestClient(app) as c:
        c.app.state.cache = BrokenCache()
        token = c.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
        ).json()["access_token"]
        created = c.post(
            "/api/v1/tenants/default/api-keys",
            headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": "default"},
            json={"scopes": ["read"]},
        )
        assert created.status_code in (200, 201), created.text
        key_id = created.json()["key_id"]
        revoked = c.delete(
            f"/api/v1/tenants/default/api-keys/{key_id}",
            headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": "default"},
        )
    assert revoked.status_code == 500, revoked.text
