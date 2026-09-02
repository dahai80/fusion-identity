from __future__ import annotations

from starlette.testclient import TestClient

TEST_SERVICE_TOKEN = "test-service-token"


def _svc_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


def test_introspect_active(client: TestClient, admin_token: str) -> None:
    resp = client.post(
        "/api/v1/auth/introspect",
        headers=_svc_headers(),
        json={"token": admin_token},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["active"] is True
    assert body["sub"] == "usr_admin"
    assert body["tenant_id"] == "default"
    assert body["token_type"] == "Bearer"
    assert "scope" in body
    assert body["exp"]


def test_introspect_form_encoded(client: TestClient, admin_token: str) -> None:
    resp = client.post(
        "/api/v1/auth/introspect",
        headers={**_svc_headers(), "Content-Type": "application/x-www-form-urlencoded"},
        data={"token": admin_token},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["active"] is True


def test_introspect_invalid_token(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/auth/introspect",
        headers=_svc_headers(),
        json={"token": "not.a.jwt"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["active"] is False


def test_introspect_empty_token(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/auth/introspect",
        headers=_svc_headers(),
        json={"token": ""},
    )
    assert resp.status_code == 200
    assert resp.json()["active"] is False


def test_introspect_revoked(client: TestClient, admin_token: str) -> None:
    import jwt as pyjwt

    claims = pyjwt.decode(
        admin_token,
        "test-signing-key-please-not-prod",
        algorithms=["HS256"],
        options={"verify_signature": False},
    )
    store = client.app.state.store
    store._revoked_jtis[claims["jti"]] = {
        "jti": claims["jti"],
        "tenant_id": "default",
        "expires_at": 0,
    }
    resp = client.post(
        "/api/v1/auth/introspect",
        headers=_svc_headers(),
        json={"token": admin_token},
    )
    assert resp.status_code == 200
    assert resp.json()["active"] is False


def test_introspect_requires_service_token(client: TestClient, admin_token: str) -> None:
    resp = client.post(
        "/api/v1/auth/introspect",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"token": admin_token},
    )
    assert resp.status_code in (401, 403)
