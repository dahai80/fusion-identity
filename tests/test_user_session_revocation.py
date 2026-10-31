from __future__ import annotations

from starlette.testclient import TestClient

from tests.conftest import TEST_SERVICE_TOKEN

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


def _issue_session(client: TestClient, sub: str, tenant_id: str = "default") -> dict:
    resp = client.post(
        "/api/v1/auth/session",
        json={"sub": sub, "tenant_id": tenant_id},
        headers=_SVC_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _verify_session(client: TestClient, token: str) -> int:
    resp = client.post(
        "/api/v1/auth/session/verify",
        json={"token": token},
        headers=_SVC_HEADERS,
    )
    return resp.status_code


def _revoke(client: TestClient, sub: str, tenant_id: str):
    return client.request(
        "DELETE",
        "/api/v1/auth/sessions",
        json={"sub": sub, "tenant_id": tenant_id},
        headers=_SVC_HEADERS,
    )


def test_revocation_kills_live_session_token(client: TestClient):
    # Issue #29 core scenario: a deleted user's session token must stop
    # passing /session/verify immediately, not at natural expiry.
    session = _issue_session(client, "usr_delete_me")
    assert _verify_session(client, session["access_token"]) == 200

    resp = _revoke(client, "usr_delete_me", "default")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["revoked_access_jtis"] >= 1

    assert _verify_session(client, session["access_token"]) == 401


def test_revocation_counts_and_idempotence(client: TestClient):
    _issue_session(client, "usr_count")
    _issue_session(client, "usr_count")
    first = _revoke(client, "usr_count", "default")
    assert first.status_code == 200
    assert first.json()["revoked_access_jtis"] == 2

    second = _revoke(client, "usr_count", "default")
    assert second.status_code == 200
    assert second.json()["revoked_access_jtis"] == 0


def test_revocation_kills_refresh_tokens(client: TestClient):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert login.status_code == 200
    body = login.json()
    refresh_token = body["refresh_token"]
    # login's access-token sub IS the user id — no extra lookup needed.
    import base64
    import json as _json

    payload = body["access_token"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    admin_id = _json.loads(base64.urlsafe_b64decode(payload))["sub"]

    resp = _revoke(client, admin_id, "default")
    assert resp.status_code == 200
    assert resp.json()["revoked_refresh_tokens"] >= 1

    # the revoked refresh token can no longer renew
    renew = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert renew.status_code == 401


def test_revocation_scoped_to_tenant(client: TestClient):
    # A session for the same sub in another tenant stays valid.
    client.post(
        "/api/v1/admin/tenants",
        json={"tenant_id": "other-co", "display_name": "Other"},
        headers=_SVC_HEADERS,
    )
    mine = _issue_session(client, "usr_shared", "default")
    theirs = _issue_session(client, "usr_shared", "other-co")

    resp = _revoke(client, "usr_shared", "other-co")
    assert resp.status_code == 200
    assert resp.json()["revoked_access_jtis"] >= 1

    assert _verify_session(client, theirs["access_token"]) == 401
    assert _verify_session(client, mine["access_token"]) == 200


def test_service_token_required_fail_closed(client: TestClient):
    no_auth = client.request(
        "DELETE", "/api/v1/auth/sessions", json={"sub": "x", "tenant_id": "default"}
    )
    assert no_auth.status_code == 401
    bad = client.request(
        "DELETE",
        "/api/v1/auth/sessions",
        json={"sub": "x", "tenant_id": "default"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert bad.status_code == 401


def test_unknown_tenant_404_fail_closed(client: TestClient):
    resp = _revoke(client, "usr_x", "ghost-tenant")
    assert resp.status_code == 404


def test_revocation_writes_audit(client: TestClient, store):
    _issue_session(client, "usr_audit")
    assert _revoke(client, "usr_audit", "default").status_code == 200
    records = [r for r in store._audit if r.get("action") == "auth.user_sessions_revoked"]
    assert len(records) == 1
    rec = records[0]
    assert rec["tenant_id"] == "default"
    assert rec["resource"] == "usr_audit"
    assert rec["detail"]["reason"] == "user_deletion"
    assert rec["detail"]["revoked_access_jtis"] >= 1
