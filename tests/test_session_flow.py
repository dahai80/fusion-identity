from __future__ import annotations

import logging

import pytest
from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN

logger = logging.getLogger(__name__)

SVC = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


def _issue_session(client: TestClient, **overrides) -> dict:
    body = {"sub": "web-shell", "tenant_id": "local", "role": "member"}
    body.update(overrides)
    resp = client.post("/api/v1/auth/session", json=body, headers=SVC)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_issue_and_verify_session_end_to_end(client: TestClient) -> None:
    issued = _issue_session(client)
    assert issued["access_token"]
    assert issued["role"] == "member"
    assert issued["expires_in"] == 43200
    resp = client.post(
        "/api/v1/auth/session/verify", json={"token": issued["access_token"]}, headers=SVC
    )
    assert resp.status_code == 200, resp.text
    claims = resp.json()
    assert claims["valid"] is True
    # R-2 #2: tenant_id claims reserved — both tid and tenant present.
    assert claims["tid"] == "local"
    assert claims["tenant"] == "local"
    assert claims["type"] == "session"


def test_local_tenant_auto_created(client: TestClient) -> None:
    _issue_session(client)
    resp = client.get("/api/v1/admin/tenants", headers=SVC | {"X-Tenant-Id": "_system"})
    assert resp.status_code == 200
    ids = [t["tenant_id"] for t in resp.json()]
    assert "local" in ids


def test_session_requires_service_token(client: TestClient) -> None:
    resp = client.post("/api/v1/auth/session", json={"sub": "x"})
    assert resp.status_code == 401
    resp = client.post("/api/v1/auth/session/verify", json={"token": "abc"})
    assert resp.status_code == 401


def test_session_nonlocal_tenant_missing_fails_closed(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/auth/session", json={"sub": "web-shell", "tenant_id": "ghost"}, headers=SVC
    )
    assert resp.status_code == 401


def test_session_ttl_clamped(client: TestClient) -> None:
    issued = _issue_session(client, ttl_seconds=86400)
    assert issued["expires_in"] == 86400
    resp = client.post(
        "/api/v1/auth/session",
        json={"sub": "web-shell", "ttl_seconds": 999999},
        headers=SVC,
    )
    assert resp.status_code == 422


def test_session_rejected_by_access_verify(client: TestClient) -> None:
    issued = _issue_session(client)
    resp = client.post("/api/v1/auth/verify", json={"token": issued["access_token"]}, headers=SVC)
    assert resp.status_code == 401


def test_session_garbage_token_rejected(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/auth/session/verify", json={"token": "junk.token.here"}, headers=SVC
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_session_revoked_jti_denied(client: TestClient, store) -> None:
    issued = _issue_session(client)
    await store.revoke_jti(issued["jti"], tenant_id="local", reason="test")
    resp = client.post(
        "/api/v1/auth/session/verify", json={"token": issued["access_token"]}, headers=SVC
    )
    assert resp.status_code == 401
