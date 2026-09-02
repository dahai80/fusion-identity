from __future__ import annotations

import dataclasses
import time

from starlette.testclient import TestClient

from fusion_identity.ratelimit import LoginRateLimiter


def _rl_settings(trusted: frozenset[str] = frozenset(), limit: int = 3):
    from tests.conftest import _settings

    s = _settings()
    return dataclasses.replace(
        s, trusted_proxies=trusted, login_rate_limit=limit, login_rate_window=60
    )


# F8: spoofed X-Forwarded-For is ignored when the peer is not a trusted proxy.
async def test_f8_xff_ignored_when_peer_untrusted():
    from fusion_identity.app import build_app
    from fusion_identity.store import InMemoryStore

    s = _rl_settings(trusted=frozenset(), limit=3)
    app = build_app(s, store=InMemoryStore(), run_bootstrap=True)
    with TestClient(app) as c:
        c.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
            headers={"X-Forwarded-For": "198.51.100.7"},
        )
        limiter = app.state.login_limiter
        # peer "testclient" not in empty trusted set → XFF ignored, bucket keyed on peer
        assert "default:198.51.100.7" not in limiter._buckets
        assert "default:testclient" in limiter._buckets, limiter._buckets


# F8: X-Forwarded-For IS honored when the peer is a trusted proxy.
async def test_f8_xff_honored_when_peer_trusted():
    from fusion_identity.app import build_app
    from fusion_identity.store import InMemoryStore

    s = _rl_settings(trusted=frozenset({"testclient"}), limit=2)
    app = build_app(s, store=InMemoryStore(), run_bootstrap=True)
    with TestClient(app) as c:
        for _ in range(2):
            c.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": "wrong", "tenant_id": "default"},
                headers={"X-Forwarded-For": "198.51.100.7"},
            )
        limiter = app.state.login_limiter
        assert "default:198.51.100.7" in limiter._buckets, limiter._buckets


# P1: _buckets capped — inserting beyond MAX_BUCKETS evicts the oldest, no
# unbounded growth.
async def test_p1_bucket_cap_evicts_oldest():
    from fusion_identity.ratelimit import MAX_BUCKETS

    limiter = LoginRateLimiter(max_tokens=10, window=60)
    base = time.time()
    for i in range(MAX_BUCKETS):
        limiter.allow("t", f"10.0.0.{i}")
    assert len(limiter._buckets) == MAX_BUCKETS
    # one more must evict — size stays bounded
    limiter.allow("t", "10.0.0.999")
    assert len(limiter._buckets) <= MAX_BUCKETS
    # sweep removes stale buckets
    removed = limiter.sweep(base + 9999)
    assert removed > 0
    assert len(limiter._buckets) < MAX_BUCKETS


# A5: cache invalidation failure propagates (not swallowed) on a mutating route.
async def test_a5_invalidation_failure_propagates(client: TestClient):
    token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-Id": "default"}

    # Inject a fake cache that raises on invalidate, plus a matching store api key
    cache = type("FakeCache", (), {})()

    async def _boom(*a, **k):
        raise RuntimeError("redis down")

    cache.invalidate_tenant = _boom
    cache.invalidate_tenant_api_keys = _boom
    client.app.state.cache = cache

    resp = client.put(
        "/api/v1/tenants/default/quotas",
        json={"tpm": 5000},
        headers=headers,
    )
    assert resp.status_code == 500, resp.text
    client.app.state.cache = None


# L4: quota PUT invalidates the api_key cache blob for that tenant.
async def test_l4_quota_put_invalidates_apikey_cache(client: TestClient):
    token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-Id": "default"}

    store = client.app.state.store
    await store.create_api_key("default", "usr_admin", scopes=["models:infer"])
    api_keys = await store.list_api_keys("default")
    assert api_keys, "expected a seeded api key"

    invalidated: list[str] = []

    cache = type("FakeCache", (), {})()

    async def _invalidate_tenant_api_keys(tenant_id, key_hashes):
        invalidated.extend(key_hashes)

    async def _invalidate_tenant(tenant_id):
        pass

    cache.invalidate_tenant_api_keys = _invalidate_tenant_api_keys
    cache.invalidate_tenant = _invalidate_tenant
    client.app.state.cache = cache

    resp = client.put(
        "/api/v1/tenants/default/quotas",
        json={"tpm": 5000},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert invalidated, "quota PUT must invalidate api_key cache blobs"
    client.app.state.cache = None
