from __future__ import annotations

import logging

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.auth import bootstrap
from fusion_identity.config import Settings
from fusion_identity.store import InMemoryStore

logging.getLogger(__name__)

TEST_JWT_KEY = "test-signing-key-please-not-prod"
TEST_SERVICE_TOKEN = "test-service-token"
PW = "pw12345678"


def _settings(bootstrap_tenants: str | None = None) -> Settings:
    return Settings(
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
        bootstrap_tenants=bootstrap_tenants,
        log_level="WARNING",
        log_json=False,
        login_rate_limit=0,
        login_rate_window=60,
        jwt_algorithm="HS256",
        jwt_private_key_pem=None,
        jwt_public_keys=None,
        kek="test-signing-key-please-not-prod",
        mfa_enforce_admin=False,
        redis_url="",
        grpc_port=0,
        lease_ttl_seconds=120,
        trusted_proxies=frozenset(),
        jwt_keyring_path="",
        db_pool_max=8,
    )


async def test_bootstrap_seeds_extra_tenants():
    store = InMemoryStore()
    extra = '[{"tenant_id":"acme","display_name":"Acme Corp","plan":"enterprise"}]'
    await bootstrap(store, "admin", "adminpass", extra)
    t = await store.get_tenant("acme")
    assert t is not None
    assert t["display_name"] == "Acme Corp"
    assert t["plan"] == "enterprise"
    q = await store.get_quota("acme")
    assert q is not None


async def test_bootstrap_invalid_tenants_json_raises():
    store = InMemoryStore()
    with pytest.raises(RuntimeError, match="invalid FUSION_BOOTSTRAP_TENANTS"):
        await bootstrap(store, "admin", "adminpass", "not-json")


async def test_bootstrap_tenant_missing_id_raises():
    store = InMemoryStore()
    with pytest.raises(RuntimeError, match="missing tenant_id"):
        await bootstrap(store, "admin", "adminpass", '[{"display_name":"x"}]')


def test_bootstrap_tenants_via_build_app():
    extra = '[{"tenant_id":"beta","display_name":"Beta","plan":"team"}]'
    settings = _settings(bootstrap_tenants=extra)
    app = build_app(settings, store=InMemoryStore(), run_bootstrap=True)
    with TestClient(app) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
        )
        assert login.status_code == 200


async def test_bootstrap_missing_creds_empty_table_fail_closed():
    # T9/F15: empty tenant table + no bootstrap creds → fail-closed. The service
    # refuses to start (RuntimeError) rather than silently coming up with no
    # admin, which would lock operators out. CLAUDE.md's "skip" note describes
    # the operator-seeding path; the F15 fix makes the code enforce it loudly.
    store = InMemoryStore()
    with pytest.raises(RuntimeError, match="FUSION_BOOTSTRAP_ADMIN"):
        await bootstrap(store, "", "")


async def test_bootstrap_missing_creds_nonempty_table_skips():
    # T9: tenants already exist → bootstrap is a no-op regardless of creds, so
    # an operator who seeded out-of-band can start the service without creds.
    store = InMemoryStore()
    await store.create_tenant("default", "Default Tenant", plan="team")
    await store.create_user("usr_admin", "admin", "adminpass")
    await store.add_member("default", "usr_admin", "tenant_admin")
    # No raise — non-empty table short-circuits before the creds check.
    await bootstrap(store, "", "")
    assert await store.get_tenant("default") is not None


async def test_delete_tenant_cascades():
    store = InMemoryStore()
    await bootstrap(store, "admin", "adminpass")
    token_user_id = "usr_test"
    await store.create_user(token_user_id, "tester", PW)
    await store.add_member("default", token_user_id, "member")
    _, key_rec = await store.create_api_key("default", token_user_id, ["models:infer"])
    jti = "jti-rt-1"
    await store.insert_refresh_token(jti, "fam-1", "default", token_user_id, 9999999999.0)

    ok = await store.delete_tenant("default")
    assert ok is True

    members = await store.list_members("default")
    assert members == []
    keys = await store.list_api_keys("default")
    assert keys == []
    rt = await store.get_refresh_token(jti)
    assert rt["status"] == "revoked"
