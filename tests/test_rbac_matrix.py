from __future__ import annotations

import asyncio
import secrets

import pytest
from fastapi.routing import APIRoute
from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}

_PASSWORD = "matrix-pass-123456"


def _make_role_user(client: TestClient, username: str, role: str) -> dict[str, str]:
    # Seed a user + membership directly in the store (bypasses the members
    # API, which is itself under test), then log in for a real token.
    store = client.app.state.store
    uid = "usr_" + secrets.token_hex(6)

    async def _seed() -> None:
        await store.create_user(uid, username, _PASSWORD)
        await store.add_member("default", uid, role, added_by="matrix-test")

    asyncio.run(_seed())
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": _PASSWORD, "tenant_id": "default"},
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}", "X-Tenant-Id": "default"}


@pytest.fixture
def viewer_headers(client: TestClient) -> dict[str, str]:
    return _make_role_user(client, "mtx_viewer", "viewer")


@pytest.fixture
def member_headers(client: TestClient) -> dict[str, str]:
    return _make_role_user(client, "mtx_member", "member")


@pytest.fixture
def operator_headers(client: TestClient) -> dict[str, str]:
    return _make_role_user(client, "mtx_operator", "operator")


def test_viewer_read_only(client: TestClient, viewer_headers: dict[str, str]):
    h = viewer_headers
    assert client.get("/api/v1/tenants/default", headers=h).status_code == 200
    assert client.get("/api/v1/tenants/default/quotas", headers=h).status_code == 200
    assert client.get("/api/v1/tenants/default/usage", headers=h).status_code == 200
    assert client.get("/api/v1/tenants/default/departments", headers=h).status_code == 200
    # viewer cannot mutate or read restricted surfaces anywhere
    assert (
        client.patch("/api/v1/tenants/default", json={"display_name": "x"}, headers=h).status_code
        == 403
    )
    assert client.get("/api/v1/tenants/default/members", headers=h).status_code == 403
    assert (
        client.post(
            "/api/v1/tenants/default/members",
            json={"username": "v_new", "password": _PASSWORD, "role": "viewer"},
            headers=h,
        ).status_code
        == 403
    )
    assert client.get("/api/v1/tenants/default/api-keys", headers=h).status_code == 403
    assert client.get("/api/v1/tenants/default/audit", headers=h).status_code == 403
    assert client.get("/api/v1/tenants/default/idps", headers=h).status_code == 403
    assert client.get("/api/v1/tenants/default/roles", headers=h).status_code == 403
    assert (
        client.put("/api/v1/tenants/default/quotas", json={"rpm": 1}, headers=h).status_code == 403
    )


def test_member_create_update_not_delete(client: TestClient, member_headers: dict[str, str]):
    h = member_headers
    assert client.get("/api/v1/tenants/default", headers=h).status_code == 200
    # member can create/update departments, not delete
    resp = client.post(
        "/api/v1/tenants/default/departments",
        json={"name": "member-dept"},
        headers=h,
    )
    assert resp.status_code == 201, resp.text
    dept_id = resp.json()["dept_id"]
    assert (
        client.patch(
            f"/api/v1/tenants/default/departments/{dept_id}", json={"name": "renamed"}, headers=h
        ).status_code
        == 200
    )
    assert (
        client.delete(f"/api/v1/tenants/default/departments/{dept_id}", headers=h).status_code
        == 403
    )
    # member cannot manage people, keys, quotas, audit, rbac
    assert client.get("/api/v1/tenants/default/members", headers=h).status_code == 403
    assert client.get("/api/v1/tenants/default/api-keys", headers=h).status_code == 403
    assert client.get("/api/v1/tenants/default/audit", headers=h).status_code == 403
    assert client.get("/api/v1/tenants/default/roles", headers=h).status_code == 403
    assert (
        client.put("/api/v1/tenants/default/quotas", json={"rpm": 1}, headers=h).status_code == 403
    )


def test_operator_operational_actions(client: TestClient, operator_headers: dict[str, str]):
    h = operator_headers
    # operator reads the roster + audit
    assert client.get("/api/v1/tenants/default/members", headers=h).status_code == 200
    assert client.get("/api/v1/tenants/default/audit", headers=h).status_code == 200
    assert client.get("/api/v1/tenants/default/audit/verify", headers=h).status_code == 200
    # operator manages api keys end to end
    resp = client.post(
        "/api/v1/tenants/default/api-keys", json={"scopes": ["inference"]}, headers=h
    )
    assert resp.status_code == 201, resp.text
    key_id = resp.json()["key_id"]
    assert client.delete(f"/api/v1/tenants/default/api-keys/{key_id}", headers=h).status_code == 200
    # operator cannot mutate members/quotas/tenant/rbac
    assert (
        client.post(
            "/api/v1/tenants/default/members",
            json={"username": "op_new", "password": _PASSWORD, "role": "member"},
            headers=h,
        ).status_code
        == 403
    )
    assert (
        client.put("/api/v1/tenants/default/quotas", json={"rpm": 1}, headers=h).status_code == 403
    )
    assert (
        client.patch("/api/v1/tenants/default", json={"display_name": "x"}, headers=h).status_code
        == 403
    )
    assert client.get("/api/v1/tenants/default/roles", headers=h).status_code == 403
    assert client.get("/api/v1/tenants/default/idps", headers=h).status_code == 403


def test_tenant_admin_full_access(client: TestClient, admin_token: str):
    h = {"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"}
    assert client.get("/api/v1/tenants/default/members", headers=h).status_code == 200
    assert client.get("/api/v1/tenants/default/roles", headers=h).status_code == 200
    assert client.get("/api/v1/tenants/default/idps", headers=h).status_code == 200
    assert client.get("/api/v1/tenants/default/audit", headers=h).status_code == 200


def test_custom_role_write_class_grants_resource(client: TestClient, admin_token: str):
    h = {"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"}
    resp = client.post(
        "/api/v1/tenants/default/roles",
        json={
            "role_id": "dept_manager",
            "display_name": "Dept Manager",
            "write_classes": ["departments:write"],
        },
        headers=h,
    )
    assert resp.status_code == 201, resp.text
    custom = _make_role_user(client, "mtx_custom", "dept_manager")
    # write class grants every action on that resource (write implies read/delete)
    assert client.get("/api/v1/tenants/default/departments", headers=custom).status_code == 200
    resp = client.post(
        "/api/v1/tenants/default/departments",
        json={"name": "custom-dept"},
        headers=custom,
    )
    assert resp.status_code == 201, resp.text
    dept_id = resp.json()["dept_id"]
    assert (
        client.delete(f"/api/v1/tenants/default/departments/{dept_id}", headers=custom).status_code
        == 200
    )
    # and nothing else (deny-by-default)
    assert client.get("/api/v1/tenants/default/members", headers=custom).status_code == 403
    assert client.get("/api/v1/tenants/default/quotas", headers=custom).status_code == 403
    assert client.get("/api/v1/tenants/default/api-keys", headers=custom).status_code == 403


def test_custom_role_unknown_resource_denied(client: TestClient, admin_token: str):
    h = {"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"}
    resp = client.post(
        "/api/v1/tenants/default/roles",
        json={
            "role_id": "fooo",
            "display_name": "Foo",
            "write_classes": ["foo:write"],
        },
        headers=h,
    )
    assert resp.status_code == 201, resp.text
    foo = _make_role_user(client, "mtx_foo", "fooo")
    assert client.get("/api/v1/tenants/default/quotas", headers=foo).status_code == 403
    assert client.get("/api/v1/tenants/default/usage", headers=foo).status_code == 403


def test_cross_tenant_denied_even_with_permission(
    client: TestClient, operator_headers: dict[str, str]
):
    client.post(
        "/api/v1/admin/tenants",
        json={"tenant_id": "other", "display_name": "Other", "plan": "free"},
        headers=_SVC_HEADERS,
    )
    h = dict(operator_headers)
    # header points at another tenant while the token is for default —
    # the tenant middleware rejects the tid mismatch (401)
    h["X-Tenant-Id"] = "other"
    assert client.get("/api/v1/tenants/other/members", headers=h).status_code == 401
    # header matches the token but the path names another tenant — the
    # permission guard's cross-tenant check rejects (403)
    h2 = dict(operator_headers)
    resp = client.get("/api/v1/tenants/other/members", headers=h2)
    assert resp.status_code == 403


def test_every_tenant_route_has_explicit_guard(client: TestClient):
    # Issue #16 deny-by-default acceptance: zero tenant-scoped routes with
    # implicit access — each must carry a marked guard dependency
    # (permission point / service token / bearer self-service).
    unguarded = []
    for route in client.app.routes:
        if not isinstance(route, APIRoute):
            continue
        if "{tenant_id}" not in route.path:
            continue
        guarded = any(
            getattr(dep.call, "__fusion_guard__", None) is not None
            for dep in route.dependant.dependencies
        )
        if not guarded:
            unguarded.append(f"{list(route.methods)[0]} {route.path}")
    assert unguarded == [], f"routes without explicit guard: {unguarded}"


def test_guard_matrix_registered(client: TestClient):
    # Every distinct permission point in use must appear in the built-in
    # matrix or be satisfiable by tenant admin/custom-role semantics.
    from fusion_identity.store import BUILTIN_ROLE_MATRIX

    resources = {res for role in BUILTIN_ROLE_MATRIX.values() for res in role}
    assert {
        "tenants",
        "members",
        "api_keys",
        "quotas",
        "audit",
        "usage",
        "departments",
    } <= resources
    # idps/rbac intentionally absent — tenant_admin-only (deny-by-default)
