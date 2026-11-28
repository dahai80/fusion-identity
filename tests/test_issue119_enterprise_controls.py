from __future__ import annotations

import logging

from starlette.testclient import TestClient

logger = logging.getLogger(__name__)

TEST_SERVICE_TOKEN = "test-service-token"
SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"


def _admin_headers(token: str, tenant: str = "default") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": tenant}


def _svc_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"}


def _admin_login(client: TestClient) -> str:
    return client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]


def _create_member(client: TestClient, admin_token: str, username: str) -> str:
    resp = client.post(
        "/api/v1/tenants/default/members",
        json={"username": username, "password": "Password123", "role": "member"},
        headers=_admin_headers(admin_token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["user_id"]


def _member_login(client: TestClient, username: str) -> dict:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "Password123", "tenant_id": "default"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_scim_create_roundtrip_spec_fixture(client: TestClient):
    # Issue #119 AC: SCIM create round-trip against a public RFC 7644 style
    # fixture (schemas + userName + name + emails + active).
    fixture = {
        "schemas": [SCIM_USER_SCHEMA],
        "userName": "factory.operator1",
        "name": {"givenName": "Factory", "familyName": "Operator"},
        "emails": [{"value": "operator1@example.com", "primary": True}],
        "displayName": "Factory Operator",
        "active": True,
    }
    resp = client.post("/scim/v2/Users?tenantId=default", json=fixture, headers=_svc_headers())
    assert resp.status_code in (200, 201), resp.text
    body = resp.json()
    assert body["schemas"] == [SCIM_USER_SCHEMA]
    assert body["meta"]["resourceType"] == "User"
    assert body["userName"] == "factory.operator1"
    assert body["active"] is True
    uid = body["id"]

    got = client.get(f"/scim/v2/Users/{uid}?tenantId=default", headers=_svc_headers())
    assert got.status_code == 200, got.text
    view = got.json()
    assert view["schemas"] == [SCIM_USER_SCHEMA]
    assert view["userName"] == "factory.operator1"
    assert view["active"] is True


def test_scim_disable_revokes_sessions_immediately(client: TestClient):
    # Issue #119 AC: a deprovisioned user cannot keep using an existing
    # session — access jti revoked, login blocked, refresh dead.
    admin_token = _admin_login(client)
    uid = _create_member(client, admin_token, "depuser")
    pair = _member_login(client, "depuser")
    access, refresh = pair["access_token"], pair["refresh_token"]
    user_headers = {"Authorization": f"Bearer {access}", "X-Tenant-Id": "default"}
    assert client.get("/api/v1/auth/settings", headers=user_headers).status_code == 200

    patch = client.patch(
        f"/scim/v2/Users/{uid}?tenantId=default",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_svc_headers(),
    )
    assert patch.status_code == 200, patch.text
    assert patch.json()["active"] is False

    verify = client.post("/api/v1/auth/verify", json={"token": access}, headers=_svc_headers())
    assert verify.status_code == 401, verify.text
    relogin = client.post(
        "/api/v1/auth/login",
        json={"username": "depuser", "password": "Password123", "tenant_id": "default"},
    )
    assert relogin.status_code == 401, relogin.text
    refresh_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert refresh_resp.status_code == 401, refresh_resp.text


def test_scim_delete_deprovision_revokes(client: TestClient):
    # SCIM DELETE = full deprovision: membership gone, status disabled,
    # outstanding tokens dead.
    admin_token = _admin_login(client)
    uid = _create_member(client, admin_token, "deluser")
    login = _member_login(client, "deluser")
    access = login["access_token"]

    resp = client.delete(f"/scim/v2/Users/{uid}?tenantId=default", headers=_svc_headers())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] is True
    assert body["revoked"]["revoked_access_jtis"] >= 1

    verify = client.post("/api/v1/auth/verify", json={"token": access}, headers=_svc_headers())
    assert verify.status_code == 401, verify.text


async def test_audit_chain_tamper_detected_after_scim_events(client: TestClient):
    # Issue #119 AC: tamper attempt detected by hash-chain re-verification.
    admin_token = _admin_login(client)
    uid = _create_member(client, admin_token, "chainuser")
    client.post(
        "/scim/v2/Users?tenantId=default",
        json={"userName": "chainuser2", "active": True},
        headers=_svc_headers(),
    )
    client.patch(
        f"/scim/v2/Users/{uid}?tenantId=default",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=_svc_headers(),
    )
    store = client.app.state.store
    assert (await store.verify_audit_chain("default"))["valid"] is True

    target = next(a for a in store._audit if a["action"] == "scim.user.patch")
    target["action"] = "forged.action"
    verdict = await store.verify_audit_chain("default")
    assert verdict["valid"] is False
    assert verdict["broken_at"] == target["id"]


def test_data_classification_admin_lifecycle(client: TestClient):
    # Issue #119: tenant-level classification flag — default standard,
    # updatable to confidential, invalid refused, cross-tenant read denied.
    admin_token = _admin_login(client)
    created = client.post(
        "/api/v1/admin/tenants",
        json={"tenant_id": "factory", "display_name": "Factory Co"},
        headers=_svc_headers(),
    )
    assert created.status_code == 201, created.text
    assert created.json()["data_classification"] == "standard"

    patched = client.put(
        "/api/v1/admin/tenants/factory",
        json={"data_classification": "confidential"},
        headers=_svc_headers(),
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["data_classification"] == "confidential"

    cross = client.get(
        "/api/v1/tenants/factory/data-classification", headers=_admin_headers(admin_token)
    )
    assert cross.status_code == 403, cross.text

    bad = client.put(
        "/api/v1/admin/tenants/factory",
        json={"data_classification": "topsecret"},
        headers=_svc_headers(),
    )
    assert bad.status_code == 409, bad.text


async def test_data_classification_tenant_read_and_audit(client: TestClient):
    admin_token = _admin_login(client)
    flagged = client.patch(
        "/api/v1/tenants/default",
        json={"data_classification": "confidential"},
        headers=_admin_headers(admin_token),
    )
    assert flagged.status_code == 200, flagged.text
    assert flagged.json()["data_classification"] == "confidential"

    read = client.get(
        "/api/v1/tenants/default/data-classification", headers=_admin_headers(admin_token)
    )
    assert read.status_code == 200, read.text
    assert read.json() == {
        "tenant_id": "default",
        "data_classification": "confidential",
        "local_only": True,
    }

    store = client.app.state.store
    assert (await store.verify_audit_chain("default"))["valid"] is True
    actions = [a["action"] for a in store._audit]
    assert "tenant.data_classification_change" in actions
