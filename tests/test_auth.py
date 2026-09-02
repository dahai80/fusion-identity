from __future__ import annotations

import logging

import pytest
from starlette.testclient import TestClient

from fusion_identity.config import ConfigError

logger = logging.getLogger(__name__)

TEST_JWT_KEY = "test-signing-key-please-not-prod"
TEST_SERVICE_TOKEN = "test-service-token"


def test_login_issues_jwt_with_tid(client: TestClient):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    access = body["access_token"]
    assert access.count(".") == 2

    import jwt

    payload = jwt.decode(
        access,
        TEST_JWT_KEY,
        algorithms=["HS256"],
        audience="fusion-cluster",
        issuer="fusion-identity",
    )
    assert payload["tid"] == "default"
    assert payload["role"] == "tenant_admin"
    assert payload["iss"] == "fusion-identity"


def test_login_bad_password_rejects_401(client: TestClient):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong", "tenant_id": "default"},
    )
    assert resp.status_code == 401


def test_verify_unknown_jti_rejects_401(client: TestClient):
    token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]
    resp = client.get(
        "/api/v1/auth/verify",
        params={"token": token},
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["tid"] == "default"


def test_verify_revoked_jti_rejects_401(client: TestClient):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()
    access = login["access_token"]

    import jwt

    claims = jwt.decode(
        access,
        TEST_JWT_KEY,
        algorithms=["HS256"],
        audience="fusion-cluster",
        issuer="fusion-identity",
    )
    revoke_resp = client.post(
        "/api/v1/auth/revoke",
        json={"jti": claims["jti"]},
        headers={"Authorization": f"Bearer {access}", "X-Tenant-Id": "default"},
    )
    assert revoke_resp.status_code == 200, revoke_resp.text

    resp = client.get(
        "/api/v1/auth/verify",
        params={"token": access},
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
    )
    assert resp.status_code == 401


def test_verify_missing_service_token_rejects_401(client: TestClient):
    token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]
    resp = client.get("/api/v1/auth/verify", params={"token": token})
    assert resp.status_code == 401


def test_missing_signing_key_fails_closed(monkeypatch):
    monkeypatch.delenv("FUSION_IDENTITY_JWT_KEY", raising=False)
    monkeypatch.delenv("FUSION_IDENTITY_SERVICE_TOKEN", raising=False)
    with pytest.raises(ConfigError):
        import fusion_identity.config as config

        config.load_settings()


def test_bootstrap_creates_default_tenant(client: TestClient):
    tenants = client.get(
        "/api/v1/tenants",
        headers={"X-Tenant-Id": "default", "Authorization": "Bearer " + _admin(client)},
    )
    assert tenants.status_code == 200
    rows = tenants.json()
    ids = [t["tenant_id"] for t in rows]
    assert "default" in ids


def _admin(client: TestClient) -> str:
    return client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]
