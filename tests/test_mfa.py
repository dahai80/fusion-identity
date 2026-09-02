from __future__ import annotations

import pyotp
from starlette.testclient import TestClient

from fusion_identity.store import InMemoryStore


def _headers(token: str, tenant: str = "default") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": tenant}


def test_mfa_enroll_returns_secret_and_uri(client: TestClient, admin_token: str) -> None:
    resp = client.post("/api/v1/auth/mfa/enroll", headers=_headers(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["method"] == "totp"
    assert body["secret"]
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    rec = client.app.state.store.get_mfa_sync("usr_admin", "totp")
    assert rec is not None


def test_mfa_verify_enables(client: TestClient, admin_token: str) -> None:
    enroll = client.post("/api/v1/auth/mfa/enroll", headers=_headers(admin_token)).json()
    code = pyotp.TOTP(enroll["secret"]).now()
    resp = client.post(
        "/api/v1/auth/mfa/verify",
        headers=_headers(admin_token),
        json={"code": code, "method": "totp"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is True


def test_mfa_verify_bad_code(client: TestClient, admin_token: str) -> None:
    client.post("/api/v1/auth/mfa/enroll", headers=_headers(admin_token))
    resp = client.post(
        "/api/v1/auth/mfa/verify",
        headers=_headers(admin_token),
        json={"code": "000000", "method": "totp"},
    )
    assert resp.status_code == 401


def test_mfa_list_and_delete(client: TestClient, admin_token: str) -> None:
    client.post("/api/v1/auth/mfa/enroll", headers=_headers(admin_token))
    lst = client.get("/api/v1/auth/mfa", headers=_headers(admin_token))
    assert lst.status_code == 200
    assert any(r["method"] == "totp" for r in lst.json())
    dele = client.delete("/api/v1/auth/mfa/totp", headers=_headers(admin_token))
    assert dele.status_code == 200
    assert dele.json()["deleted"] is True
    lst2 = client.get("/api/v1/auth/mfa", headers=_headers(admin_token))
    assert lst2.json() == []


def test_login_mfa_required_then_success(client: TestClient, admin_token: str) -> None:
    enroll = client.post("/api/v1/auth/mfa/enroll", headers=_headers(admin_token)).json()
    code = pyotp.TOTP(enroll["secret"]).now()
    client.post(
        "/api/v1/auth/mfa/verify",
        headers=_headers(admin_token),
        json={"code": code, "method": "totp"},
    )
    no_code = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert no_code.status_code == 200
    assert no_code.json()["mfa_required"] is True
    assert no_code.json()["access_token"] == ""
    good = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "adminpass",
            "tenant_id": "default",
            "mfa_code": pyotp.TOTP(enroll["secret"]).now(),
        },
    )
    assert good.status_code == 200, good.text
    assert good.json()["mfa_required"] is False
    assert good.json()["access_token"]


def test_login_mfa_bad_code(client: TestClient, admin_token: str) -> None:
    enroll = client.post("/api/v1/auth/mfa/enroll", headers=_headers(admin_token)).json()
    code = pyotp.TOTP(enroll["secret"]).now()
    client.post(
        "/api/v1/auth/mfa/verify",
        headers=_headers(admin_token),
        json={"code": code, "method": "totp"},
    )
    bad = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "adminpass",
            "tenant_id": "default",
            "mfa_code": "000000",
        },
    )
    assert bad.status_code == 401


def test_admin_mfa_enforcement(client: TestClient, store: InMemoryStore) -> None:
    client.app.state.auth_service._mfa_enforce_admin = True
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert resp.status_code == 401
    assert "mfa" in resp.text.lower()
    client.app.state.auth_service._mfa_enforce_admin = False
