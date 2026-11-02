from __future__ import annotations

from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


def _summary(client: TestClient, tenant_id: str, zone: str):
    return client.get(f"/api/v1/admin/tenants/{tenant_id}/{zone}/summary", headers=_SVC_HEADERS)


def test_member_summary_counts_bootstrapped_admin(client: TestClient):
    resp = _summary(client, "default", "members")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    assert body["active"] == 1
    assert body["disabled"] == 0
    assert body["locked"] == 0
    assert body["by_role"] == {"tenant_admin": 1}


def test_member_summary_counts_by_status_and_role(client: TestClient, admin_token: str):
    headers = {"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"}
    created = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "sumuser", "password": "Password123", "role": "member"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    user_id = created.json()["user_id"]
    disabled = client.patch(
        f"/api/v1/tenants/default/members/{user_id}/status",
        json={"status": "disabled"},
        headers=headers,
    )
    assert disabled.status_code == 200, disabled.text

    body = _summary(client, "default", "members").json()
    assert body["total"] == 2
    assert body["active"] == 1
    assert body["disabled"] == 1
    assert body["by_role"] == {"tenant_admin": 1, "member": 1}
    # counts only — no usernames/emails anywhere in the payload
    assert "sumuser" not in str(body)


def test_member_summary_unknown_tenant_404(client: TestClient):
    assert _summary(client, "no-such-tenant", "members").status_code == 404


def test_idp_summary_unconfigured(client: TestClient):
    body = _summary(client, "default", "idps").json()
    assert body == {
        "configured": False,
        "count": 0,
        "types": [],
        "auto_provision": False,
    }


def test_idp_summary_after_create(client: TestClient, admin_token: str):
    resp = client.post(
        "/api/v1/tenants/default/idps",
        json={
            "idp_id": "sum-idp",
            "type": "oidc",
            "issuer_url": "https://idp.example.com",
            "client_id": "cid",
            "client_secret": "csecret",
            "auto_provision": True,
        },
        headers={"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"},
    )
    assert resp.status_code == 201, resp.text
    body = _summary(client, "default", "idps").json()
    assert body == {
        "configured": True,
        "count": 1,
        "types": ["oidc"],
        "auto_provision": True,
    }
    # capability state only — never secret material
    assert "csecret" not in str(body)
    assert "client_secret" not in str(body)


def test_idp_summary_unknown_tenant_404(client: TestClient):
    assert _summary(client, "no-such-tenant", "idps").status_code == 404


def test_app_secret_inventory_across_apps(client: TestClient):
    assert (
        client.post("/api/v1/apps/inv-app-a/secrets", json={}, headers=_SVC_HEADERS).status_code
        == 201
    )
    assert (
        client.post("/api/v1/apps/inv-app-b/secrets", json={}, headers=_SVC_HEADERS).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/apps/inv-app-b/secrets/rotate",
            json={"grace_seconds": 60},
            headers=_SVC_HEADERS,
        ).status_code
        == 201
    )

    resp = client.get("/api/v1/admin/app-secrets", headers=_SVC_HEADERS)
    assert resp.status_code == 200, resp.text
    apps = {a["app_id"]: a for a in resp.json()["apps"]}
    assert set(apps) >= {"inv-app-a", "inv-app-b"}
    assert apps["inv-app-a"]["versions"] == 1
    assert apps["inv-app-a"]["current_version"] == 1
    assert apps["inv-app-a"]["status"] == "active"
    assert apps["inv-app-b"]["versions"] == 2
    assert apps["inv-app-b"]["current_version"] == 2
    assert apps["inv-app-b"]["status"] == "active"
    assert apps["inv-app-b"]["grace_until"] is not None
    # never any key material
    assert "secret" not in str(apps)
    assert "fms_" not in str(apps)


def test_app_secret_inventory_inactive_after_revoke_all(client: TestClient):
    assert (
        client.post("/api/v1/apps/rev-app/secrets", json={}, headers=_SVC_HEADERS).status_code
        == 201
    )
    resp = client.delete("/api/v1/apps/rev-app/secrets/1", headers=_SVC_HEADERS)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "revoked"
    assert resp.json()["grace_until"] is None

    listed = client.get("/api/v1/apps/rev-app/secrets", headers=_SVC_HEADERS).json()
    assert listed[0]["status"] == "revoked"

    apps = {
        a["app_id"]: a
        for a in client.get("/api/v1/admin/app-secrets", headers=_SVC_HEADERS).json()["apps"]
    }
    assert apps["rev-app"]["status"] == "inactive"
    assert apps["rev-app"]["current_version"] is None


def test_revoke_cuts_grace_window_short(client: TestClient):
    assert (
        client.post("/api/v1/apps/grace-app/secrets", json={}, headers=_SVC_HEADERS).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/apps/grace-app/secrets/rotate",
            json={"grace_seconds": 3600},
            headers=_SVC_HEADERS,
        ).status_code
        == 201
    )
    resp = client.delete("/api/v1/apps/grace-app/secrets/1", headers=_SVC_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 1
    assert body["status"] == "revoked"
    assert body["grace_until"] is None


def test_revoke_unknown_version_404(client: TestClient):
    assert (
        client.post("/api/v1/apps/unk-app/secrets", json={}, headers=_SVC_HEADERS).status_code
        == 201
    )
    assert client.delete("/api/v1/apps/unk-app/secrets/99", headers=_SVC_HEADERS).status_code == 404
    assert (
        client.delete("/api/v1/apps/no-such-app/secrets/1", headers=_SVC_HEADERS).status_code == 404
    )


def test_aggregation_requires_service_token(client: TestClient):
    assert client.get("/api/v1/admin/app-secrets").status_code == 401
    assert client.get("/api/v1/admin/tenants/default/members/summary").status_code == 401
    assert client.get("/api/v1/admin/tenants/default/idps/summary").status_code == 401
    assert client.delete("/api/v1/apps/x/secrets/1").status_code == 401


def test_revoke_audited(client: TestClient, store):
    assert (
        client.post("/api/v1/apps/aud-rev-app/secrets", json={}, headers=_SVC_HEADERS).status_code
        == 201
    )
    assert (
        client.delete("/api/v1/apps/aud-rev-app/secrets/1", headers=_SVC_HEADERS).status_code == 200
    )
    records = [r for r in store._audit if r.get("action") == "app_secret.revoked"]
    assert len(records) == 1
    assert records[0]["tenant_id"] == "_system"
    assert records[0]["resource"] == "aud-rev-app"
    assert records[0]["detail"]["version"] == 1
