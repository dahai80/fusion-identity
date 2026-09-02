from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.config import Settings
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

TEST_JWT_KEY = "test-signing-key-please-not-prod"
TEST_SERVICE_TOKEN = "test-service-token"


def _settings() -> Settings:
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
        bootstrap_tenants=None,
        log_level="WARNING",
        log_json=False,
        login_rate_limit=0,
        login_rate_window=60,
        jwt_algorithm="HS256",
        jwt_private_key_pem=None,
        jwt_public_keys=None,
        kek=TEST_JWT_KEY,
        mfa_enforce_admin=False,
        redis_url="",
        grpc_port=0,
        lease_ttl_seconds=120,
    )


@pytest.fixture
def settings() -> Settings:
    return _settings()


@pytest.fixture
def store() -> InMemoryStore:
    return InMemoryStore()


@pytest.fixture
def app(settings: Settings, store: InMemoryStore):
    return build_app(settings, store=store, run_bootstrap=True)


@pytest.fixture
def client(app) -> AsyncIterator[TestClient]:
    with TestClient(app) as c:
        c.app.state.settings = app.state.settings
        c.app.state.store = app.state.store
        c.app.state.auth_service = app.state.auth_service
        yield c


def _admin_token(client: TestClient, tenant_id: str = "default") -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": tenant_id},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def admin_token(client: TestClient) -> str:
    return _admin_token(client)
