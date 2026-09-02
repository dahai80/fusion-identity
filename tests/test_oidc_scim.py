from __future__ import annotations

import logging

import pytest
from starlette.testclient import TestClient

from fusion_identity.crypto import decrypt_secret, encrypt_secret

logger = logging.getLogger(__name__)

TEST_SERVICE_TOKEN = "test-service-token"


def _admin_headers(token: str, tenant: str = "default") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": tenant}


def _svc_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


@pytest.fixture
def idp_setup(client: TestClient) -> dict:
    token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]
    resp = client.post(
        "/api/v1/tenants/default/idps",
        json={
            "idp_id": "keycloak",
            "type": "oidc",
            "issuer_url": "http://idp.example/realms/test",
            "client_id": "fusion",
            "client_secret": "supersecret",
            "scopes": "openid profile email",
            "auto_provision": True,
        },
        headers=_admin_headers(token),
    )
    assert resp.status_code == 201, resp.text
    return {"token": token, "idp": resp.json()}


def test_create_idp_stores_secret_encrypted(client: TestClient, idp_setup: dict):
    store = client.app.state.store
    rec = store._idps["keycloak"]
    assert rec["client_secret_enc"] != "supersecret"
    kek = client.app.state.settings.kek
    assert decrypt_secret(rec["client_secret_enc"], kek) == "supersecret"


def test_create_idp_response_omits_secret(idp_setup: dict):
    body = idp_setup["idp"]
    assert "client_secret_enc" not in body
    assert "client_secret" not in body
    assert body["idp_id"] == "keycloak"
    assert body["auto_provision"] is True


def test_list_idps(client: TestClient, idp_setup: dict):
    resp = client.get("/api/v1/tenants/default/idps", headers=_admin_headers(idp_setup["token"]))
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["idp_id"] == "keycloak"


def test_idp_crud_requires_tenant_admin(client: TestClient):
    resp = client.post(
        "/api/v1/tenants/default/idps",
        json={"idp_id": "x"},
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert resp.status_code in (401, 403)


def test_delete_idp(client: TestClient, idp_setup: dict):
    resp = client.delete(
        "/api/v1/tenants/default/idps/keycloak", headers=_admin_headers(idp_setup["token"])
    )
    assert resp.status_code == 200, resp.text
    store = client.app.state.store
    assert "keycloak" not in store._idps


def test_oidc_login_redirects(client: TestClient, idp_setup: dict):
    resp = client.get("/api/v1/auth/oidc/keycloak/login", follow_redirects=False)
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert "idp.example" in loc
    assert "client_id=fusion" in loc
    assert "response_type=code" in loc


def test_oidc_login_unknown_idp_404(client: TestClient):
    resp = client.get("/api/v1/auth/oidc/nope/login", follow_redirects=False)
    assert resp.status_code == 404


def test_scim_create_user_auto_provision(client: TestClient):
    resp = client.post(
        "/scim/v2/Users?tenantId=default",
        json={"userName": "scimuser@example.com", "displayName": "SCIM User"},
        headers=_svc_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["userName"] == "scimuser@example.com"
    assert body["tenant_id"] == "default"
    store = client.app.state.store
    assert body["id"] in store._users
    assert ("default", body["id"]) in set(store._members.keys())


def test_scim_list_users(client: TestClient):
    client.post(
        "/scim/v2/Users?tenantId=default",
        json={"userName": "scimlist@example.com"},
        headers=_svc_headers(),
    )
    resp = client.get("/scim/v2/Users?tenantId=default", headers=_svc_headers())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["totalResults"] >= 1
    assert any(r["userName"] == "scimlist@example.com" for r in body["Resources"])


def test_scim_requires_service_token(client: TestClient):
    resp = client.get("/scim/v2/Users?tenantId=default")
    assert resp.status_code == 401


def test_scim_duplicate_user_409(client: TestClient):
    client.post(
        "/scim/v2/Users?tenantId=default",
        json={"userName": "dup@example.com"},
        headers=_svc_headers(),
    )
    resp = client.post(
        "/scim/v2/Users?tenantId=default",
        json={"userName": "dup@example.com"},
        headers=_svc_headers(),
    )
    assert resp.status_code == 409


def test_scim_get_user_by_id(client: TestClient):
    create = client.post(
        "/scim/v2/Users?tenantId=default",
        json={"userName": "getbyid@example.com", "displayName": "Get ById"},
        headers=_svc_headers(),
    )
    uid = create.json()["id"]
    resp = client.get(
        f"/scim/v2/Users/{uid}?tenantId=default",
        headers=_svc_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["id"] == uid
    assert resp.json()["displayName"] == "Get ById"


def test_scim_get_user_not_found_404(client: TestClient):
    resp = client.get(
        "/scim/v2/Users/usr_nonexistent?tenantId=default",
        headers=_svc_headers(),
    )
    assert resp.status_code == 404


def test_scim_patch_user(client: TestClient):
    create = client.post(
        "/scim/v2/Users?tenantId=default",
        json={"userName": "patchme@example.com", "displayName": "Before"},
        headers=_svc_headers(),
    )
    uid = create.json()["id"]
    resp = client.patch(
        f"/scim/v2/Users/{uid}?tenantId=default",
        json={"displayName": "After", "active": False},
        headers=_svc_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["displayName"] == "After"
    assert body["active"] is False


def test_scim_delete_user(client: TestClient):
    create = client.post(
        "/scim/v2/Users?tenantId=default",
        json={"userName": "deleteme@example.com"},
        headers=_svc_headers(),
    )
    uid = create.json()["id"]
    resp = client.delete(
        f"/scim/v2/Users/{uid}?tenantId=default",
        headers=_svc_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] is True
    store = client.app.state.store
    assert ("default", uid) not in set(store._members.keys())


def test_scim_cross_tenant_user_404(client: TestClient):
    create = client.post(
        "/scim/v2/Users?tenantId=default",
        json={"userName": "ct@example.com"},
        headers=_svc_headers(),
    )
    uid = create.json()["id"]
    resp = client.get(
        f"/scim/v2/Users/{uid}?tenantId=other",
        headers=_svc_headers(),
    )
    assert resp.status_code == 404


def test_get_idp_by_id(client: TestClient, idp_setup: dict):
    resp = client.get(
        "/api/v1/tenants/default/idps/keycloak",
        headers=_admin_headers(idp_setup["token"]),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["idp_id"] == "keycloak"
    assert "client_secret_enc" not in resp.json()


def test_get_idp_not_found_404(client: TestClient, idp_setup: dict):
    resp = client.get(
        "/api/v1/tenants/default/idps/nope",
        headers=_admin_headers(idp_setup["token"]),
    )
    assert resp.status_code == 404


def test_patch_idp(client: TestClient, idp_setup: dict):
    resp = client.patch(
        "/api/v1/tenants/default/idps/keycloak",
        json={"issuer_url": "http://idp.example/realms/updated", "auto_provision": False},
        headers=_admin_headers(idp_setup["token"]),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issuer_url"] == "http://idp.example/realms/updated"
    assert body["auto_provision"] is False


def test_patch_idp_rotates_secret(client: TestClient, idp_setup: dict):
    resp = client.patch(
        "/api/v1/tenants/default/idps/keycloak",
        json={"client_secret": "newsecret"},
        headers=_admin_headers(idp_setup["token"]),
    )
    assert resp.status_code == 200, resp.text
    store = client.app.state.store
    rec = store._idps["keycloak"]
    kek = client.app.state.settings.kek
    assert decrypt_secret(rec["client_secret_enc"], kek) == "newsecret"


def test_crypto_roundtrip():
    blob = encrypt_secret("hello", "kek-material")
    assert blob != "hello"
    assert decrypt_secret(blob, "kek-material") == "hello"
