from __future__ import annotations

import logging

import pytest
from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN, _admin_token

logger = logging.getLogger(__name__)

SVC = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "default"}


def _admin_headers(client: TestClient) -> dict:
    return {"Authorization": f"Bearer {_admin_token(client)}", "X-Tenant-Id": "default"}


def _verify_token(client: TestClient, token: str) -> dict:
    resp = client.post("/api/v1/auth/verify", json={"token": token}, headers=SVC)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _create_member(client: TestClient, headers: dict, username: str, role: str) -> tuple[str, str]:
    resp = client.post(
        "/api/v1/tenants/default/members",
        json={"username": username, "password": "Sup3rSecret9", "role": role},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    login = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "Sup3rSecret9", "tenant_id": "default"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"], login.json()["refresh_token"]


def test_custom_role_end_to_end_verify_enforced(client: TestClient) -> None:
    # Issue #12 acceptance: admin creates a custom role with write classes,
    # maps menus via the matrix, and a user with that role sees exactly those
    # menus / granted write classes — enforced in the verify response.
    headers = _admin_headers(client)

    resp = client.post(
        "/api/v1/tenants/default/menus",
        json={"menus": ["agents", "kb", "trainer"]},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    assert set(resp.json()["menus"]) >= {"agents", "kb", "trainer"}

    resp = client.post(
        "/api/v1/tenants/default/roles",
        json={
            "role_id": "content_editor",
            "display_name": "Content Editor",
            "write_classes": ["agents:write", "kb:write"],
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text

    resp = client.put(
        "/api/v1/tenants/default/roles/content_editor/menus",
        json={"menus": ["dashboard", "agents", "kb"]},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    token, _ = _create_member(client, headers, "editor1", "content_editor")
    grants = _verify_token(client, token)
    assert grants["role"] == "content_editor"
    assert grants["write_classes"] == ["agents:write", "kb:write"]
    assert grants["allowed_menus"] == ["dashboard", "agents", "kb"]


def test_builtin_roles_immutable(client: TestClient) -> None:
    headers = _admin_headers(client)
    resp = client.patch(
        "/api/v1/tenants/default/roles/tenant_admin",
        json={"write_classes": ["tenants:write"]},
        headers=headers,
    )
    assert resp.status_code == 403
    resp = client.delete("/api/v1/tenants/default/roles/tenant_admin", headers=headers)
    assert resp.status_code == 403
    resp = client.post(
        "/api/v1/tenants/default/roles",
        json={"role_id": "tenant_admin", "display_name": "Fake Admin"},
        headers=headers,
    )
    assert resp.status_code == 409


def test_builtin_default_menus_in_verify(client: TestClient) -> None:
    headers = _admin_headers(client)
    grants = _verify_token(client, _admin_token(client))
    assert grants["role"] == "tenant_admin"
    assert "users" in grants["allowed_menus"]
    assert "tenants:write" in grants["write_classes"]
    # role list includes built-ins with their defaults
    roles = client.get("/api/v1/tenants/default/roles", headers=headers).json()
    admin_row = next(r for r in roles if r["role_id"] == "tenant_admin")
    assert admin_row["built_in"] is True
    assert admin_row["menus"] == grants["allowed_menus"]


def test_matrix_survives_restart(client: TestClient) -> None:
    # Issue #12 acceptance: the matrix survives a restart — rebuild the app
    # over the SAME store and re-verify the grants.
    headers = _admin_headers(client)
    client.post("/api/v1/tenants/default/menus", json={"menus": ["reports"]}, headers=headers)
    client.post(
        "/api/v1/tenants/default/roles",
        json={"role_id": "auditor", "display_name": "Auditor", "write_classes": []},
        headers=headers,
    )
    client.put(
        "/api/v1/tenants/default/roles/auditor/menus",
        json={"menus": ["dashboard", "reports"]},
        headers=headers,
    )
    token, _ = _create_member(client, headers, "auditor1", "auditor")

    from fusion_identity.app import build_app as _ba

    store = client.app.state.store
    settings = client.app.state.settings
    with TestClient(_ba(settings, store=store, run_bootstrap=False)) as c2:
        grants = _verify_token(c2, token)
        assert grants["allowed_menus"] == ["dashboard", "reports"]
        assert grants["write_classes"] == []


def test_role_delete_guard_and_reuse(client: TestClient) -> None:
    headers = _admin_headers(client)
    client.post(
        "/api/v1/tenants/default/roles",
        json={"role_id": "temp_role", "display_name": "Temp"},
        headers=headers,
    )
    _create_member(client, headers, "tempuser1", "temp_role")
    resp = client.delete("/api/v1/tenants/default/roles/temp_role", headers=headers)
    assert resp.status_code == 409
    # last-admin guard rail (issue #12): cannot disable/demote the only admin
    admin_id = client.get("/api/v1/tenants/default/members", headers=headers).json()[0]["user_id"]
    resp = client.patch(
        f"/api/v1/tenants/default/members/{admin_id}/status",
        json={"status": "disabled"},
        headers=headers,
    )
    assert resp.status_code == 403
    resp = client.patch(
        f"/api/v1/tenants/default/members/{admin_id}",
        json={"role": "temp_role"},
        headers=headers,
    )
    assert resp.status_code == 403


def test_unregistered_menu_denied(client: TestClient) -> None:
    headers = _admin_headers(client)
    resp = client.put(
        "/api/v1/tenants/default/roles/viewer/menus",
        json={"menus": ["dashboard", "ghost_menu"]},
        headers=headers,
    )
    assert resp.status_code == 409


def test_reset_menu_matrix(client: TestClient) -> None:
    headers = _admin_headers(client)
    client.post("/api/v1/tenants/default/menus", json={"menus": ["extra"]}, headers=headers)
    client.put(
        "/api/v1/tenants/default/roles/viewer/menus",
        json={"menus": ["extra"]},
        headers=headers,
    )
    got = client.get("/api/v1/tenants/default/roles/viewer/menus", headers=headers).json()
    assert got["menus"] == ["extra"]
    resp = client.post("/api/v1/tenants/default/roles/viewer/menus/reset", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["menus"] == ["dashboard", "models"]


def test_approval_validate_requester_ne_approver(client: TestClient) -> None:
    headers = _admin_headers(client)
    _create_member(client, headers, "req1", "member")
    # need requester's user_id — fetch members list
    members = client.get("/api/v1/tenants/default/members", headers=headers).json()
    req_id = next(m["user_id"] for m in members if m["role"] == "member")
    admin_id = next(m["user_id"] for m in members if m["role"] == "tenant_admin")

    resp = client.post(
        "/api/v1/tenants/default/approvals/validate",
        json={"requester_id": req_id, "approver_id": admin_id},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True

    resp = client.post(
        "/api/v1/tenants/default/approvals/validate",
        json={"requester_id": admin_id, "approver_id": admin_id},
        headers=headers,
    )
    assert resp.status_code == 403

    resp = client.post(
        "/api/v1/tenants/default/approvals/validate",
        json={"requester_id": "usr_missing", "approver_id": admin_id},
        headers=headers,
    )
    assert resp.status_code == 404


def test_unknown_role_assignment_denied(client: TestClient) -> None:
    headers = _admin_headers(client)
    resp = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "ghost1", "password": "Sup3rSecret9", "role": "no_such_role"},
        headers=headers,
    )
    assert resp.status_code == 400


def test_cross_tenant_custom_role_denied(client: TestClient) -> None:
    headers = _admin_headers(client)
    client.post(
        "/api/v1/tenants/default/roles",
        json={"role_id": "only_here", "display_name": "Local Only"},
        headers=headers,
    )
    resp = client.post(
        "/api/v1/admin/tenants",
        json={"tenant_id": "tenant_b", "display_name": "Tenant B"},
        headers=SVC,
    )
    assert resp.status_code in (200, 201), resp.text
    # Red line #2: default's admin token cannot act on tenant_b at all.
    b_headers = {"Authorization": headers["Authorization"], "X-Tenant-Id": "tenant_b"}
    resp = client.post(
        "/api/v1/tenants/tenant_b/members",
        json={"username": "buser1", "password": "Sup3rSecret9", "role": "only_here"},
        headers=b_headers,
    )
    assert resp.status_code in (401, 403)
    # Role scoping: custom role of default does not resolve in tenant_b.
    import asyncio

    from fusion_identity.store import StoreConflict

    store = client.app.state.store
    assert asyncio.run(store.is_valid_role("tenant_b", "only_here")) is False
    with pytest.raises(StoreConflict):
        asyncio.run(store.add_member("tenant_b", "usr_any", "only_here"))
