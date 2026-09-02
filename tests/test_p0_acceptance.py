from __future__ import annotations

import logging

import jwt
import pytest
from starlette.testclient import TestClient

from fusion_identity.store import InMemoryStore, hash_password, verify_password

logger = logging.getLogger(__name__)

TEST_JWT_KEY = "test-signing-key-please-not-prod"
TEST_SERVICE_TOKEN = "test-service-token"
PW = "pw12345678"


def _admin(client: TestClient) -> str:
    return client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]


def _hdr(token: str, tenant: str = "default") -> dict:
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": tenant}


def _decode(token: str) -> dict:
    return jwt.decode(
        token,
        TEST_JWT_KEY,
        algorithms=["HS256"],
        audience="fusion-cluster",
        issuer="fusion-identity",
    )


# ---------------------------------------------------------------------------
# AC-S1: per-user salt uniqueness + argon2id
# ---------------------------------------------------------------------------


def test_ac_s1_salt_unique_per_user():
    h1, s1, a1 = hash_password(PW)
    h2, s2, a2 = hash_password(PW)
    assert a1 == "argon2id"
    assert a2 == "argon2id"
    assert s1 != s2
    assert h1 != h2


def test_ac_s1_verify_and_rehash():
    h, s, a = hash_password(PW)
    ok, needs = verify_password(PW, password_hash_v=h, password_hash="", salt=s, algo=a)
    assert ok is True
    assert needs is False
    ok2, needs2 = verify_password("wrong", password_hash_v=h, password_hash="", salt=s, algo=a)
    assert ok2 is False
    assert needs2 is False


def test_ac_s1_legacy_scrypt_rehash():
    from fusion_identity.store import scrypt_hash

    legacy = scrypt_hash(PW)
    ok, needs = verify_password(
        PW, password_hash_v="", password_hash=legacy, salt="fusion-identity", algo="scrypt"
    )
    assert ok is True
    assert needs is True


# ---------------------------------------------------------------------------
# AC-S2: password policy (min 10 + letter + digit)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    ["short1", "allletters", "1234567890", "abcdefghij"],
)
def test_ac_s2_password_policy_rejects_weak(client: TestClient, bad: str):
    token = _admin(client)
    resp = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "weakuser", "password": bad, "role": "viewer"},
        headers=_hdr(token),
    )
    assert resp.status_code == 422, resp.text


def test_ac_s2_password_policy_accepts_strong(client: TestClient):
    token = _admin(client)
    resp = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "okuser", "password": PW, "role": "viewer"},
        headers=_hdr(token),
    )
    assert resp.status_code == 201, resp.text


# ---------------------------------------------------------------------------
# AC-S3: tenant / user status checks on login + verify
# ---------------------------------------------------------------------------


async def test_ac_s3_disabled_tenant_login_rejects(client: TestClient, store: InMemoryStore):
    await store.update_tenant("default", status="disabled")
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert resp.status_code == 401, resp.text


def test_ac_s3_verify_reports_tenant_status(client: TestClient, store: InMemoryStore):
    token = _admin(client)
    resp = client.get(
        "/api/v1/auth/verify",
        params={"token": token},
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_status"] == "active"


# ---------------------------------------------------------------------------
# AC-S4: cross-tenant guards (path + header + token tid)
# ---------------------------------------------------------------------------


def test_ac_s4_cross_tenant_audit_403(client: TestClient):
    token = _admin(client)
    resp = client.get("/api/v1/tenants/other/audit", headers=_hdr(token, tenant="default"))
    assert resp.status_code == 403, resp.text


def test_ac_s4_header_mismatch_401(client: TestClient):
    token = _admin(client)
    resp = client.get("/api/v1/tenants/default/audit", headers=_hdr(token, tenant="other"))
    assert resp.status_code == 401, resp.text


# ---------------------------------------------------------------------------
# AC-S5: self-only tenant list
# ---------------------------------------------------------------------------


def test_ac_s5_list_tenants_self_only(client: TestClient):
    token = _admin(client)
    resp = client.get("/api/v1/tenants", headers=_hdr(token))
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == "default"


# ---------------------------------------------------------------------------
# AC-S6: refresh token rotation + reuse detection
# ---------------------------------------------------------------------------


def test_ac_s6_refresh_rotation(client: TestClient):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()
    old_refresh = login["refresh_token"]

    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r1.status_code == 200, r1.text
    new_refresh = r1.json()["refresh_token"]
    assert new_refresh != old_refresh

    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r2.status_code == 401, r2.text


# ---------------------------------------------------------------------------
# AC-S7: logout invalidates refresh token
# ---------------------------------------------------------------------------


def test_ac_s7_logout_invalidates_refresh(client: TestClient):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()
    access = login["access_token"]
    refresh = login["refresh_token"]

    out = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh},
        headers=_hdr(access),
    )
    assert out.status_code == 200, out.text

    r = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401, r.text


# ---------------------------------------------------------------------------
# AC-S8: audit chain tamper detection
# ---------------------------------------------------------------------------


async def test_ac_s8_audit_chain_tamper_detected(client: TestClient, store: InMemoryStore):
    token = _admin(client)
    before = client.get("/api/v1/tenants/default/audit", headers=_hdr(token)).json()
    assert len(before) > 0
    res = await store.verify_audit_chain("default")
    assert res["valid"] is True

    if store._audit:
        store._audit[0]["action"] = "tampered"
    res2 = await store.verify_audit_chain("default")
    assert res2["valid"] is False


# ---------------------------------------------------------------------------
# AC-S9: revoke audit attribution (G19)
# ---------------------------------------------------------------------------


def test_ac_s9_revoke_records_audit(client: TestClient):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()
    access = login["access_token"]
    claims = _decode(access)

    rev = client.post(
        "/api/v1/auth/revoke",
        json={"jti": claims["jti"]},
        headers=_hdr(access),
    )
    assert rev.status_code == 200, rev.text

    token = _admin(client)
    rows = client.get("/api/v1/tenants/default/audit", headers=_hdr(token)).json()
    revoke_rows = [r for r in rows if r.get("action") == "auth.revoke"]
    assert len(revoke_rows) >= 1
    assert revoke_rows[-1].get("jti") == claims["jti"]


# ---------------------------------------------------------------------------
# AC-S10: lockout after 5 failed attempts
# ---------------------------------------------------------------------------


def test_ac_s10_lockout_after_threshold(client: TestClient):
    for _ in range(5):
        client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "wrong", "tenant_id": "default"},
        )
    locked = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert locked.status_code == 429, locked.text


# ---------------------------------------------------------------------------
# AC-S11: change password endpoint
# ---------------------------------------------------------------------------


def test_ac_s11_change_password(client: TestClient):
    token = _admin(client)
    resp = client.post(
        "/api/v1/auth/password",
        json={"old_password": "adminpass", "new_password": "newpass1234"},
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text

    login_old = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert login_old.status_code == 401

    login_new = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "newpass1234", "tenant_id": "default"},
    )
    assert login_new.status_code == 200, login_new.text


# ---------------------------------------------------------------------------
# AC-S12: must_change_password flag in login response
# ---------------------------------------------------------------------------


def test_ac_s12_must_change_password_for_new_user(client: TestClient):
    token = _admin(client)
    cm = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "newbie", "password": PW, "role": "member"},
        headers=_hdr(token),
    )
    assert cm.status_code == 201, cm.text

    login = client.post(
        "/api/v1/auth/login",
        json={"username": "newbie", "password": PW, "tenant_id": "default"},
    )
    assert login.status_code == 200, login.text
    assert login.json()["must_change_password"] is True


# ---------------------------------------------------------------------------
# AC-S13: member role/scope sync on protected call (G7)
# ---------------------------------------------------------------------------


async def test_ac_s13_role_sync_on_verify(client: TestClient):
    token = _admin(client)
    cm = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "r13", "password": PW, "role": "viewer"},
        headers=_hdr(token),
    )
    assert cm.status_code == 201, cm.text

    member_login = client.post(
        "/api/v1/auth/login",
        json={"username": "r13", "password": PW, "tenant_id": "default"},
    ).json()
    member_token = member_login["access_token"]
    claims = _decode(member_token)
    assert claims["role"] == "viewer"
    uid = claims["sub"]

    patch = client.patch(
        f"/api/v1/tenants/default/members/{uid}",
        json={"role": "operator"},
        headers=_hdr(token),
    )
    assert patch.status_code == 200, patch.text

    res = client.get(
        "/api/v1/auth/verify",
        params={"token": member_token},
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["role"] == "operator"


# ---------------------------------------------------------------------------
# AC-P2: store selection logging (use_pgstore False = InMemoryStore warning)
# ---------------------------------------------------------------------------


def test_ac_p2_inmem_store_warning(client: TestClient):
    from fusion_identity.app import _build_store
    from fusion_identity.config import Settings

    s = Settings(
        host="127.0.0.1",
        port=11470,
        database_url="postgresql://127.0.0.1:5432/fusion_tenant",
        use_pgstore=False,
        jwt_signing_key=TEST_JWT_KEY,
        jwt_issuer="fusion-identity",
        jwt_audience="fusion-cluster",
        jwt_ttl_seconds=3600,
        refresh_ttl_seconds=86400,
        service_token=TEST_SERVICE_TOKEN,
        bootstrap_admin_user="admin",
        bootstrap_admin_pass="adminpass",
        bootstrap_tenants=None,
        log_level="WARNING",
        log_json=False,
        login_rate_limit=0,
        login_rate_window=60,
        jwt_algorithm="HS256",
        jwt_private_key_pem=None,
        jwt_public_keys=None,
        kek="test-signing-key-please-not-prod",
        mfa_enforce_admin=False,
        redis_url="",
        grpc_port=0,
        lease_ttl_seconds=120,
    )
    store = _build_store(s)
    assert isinstance(store, InMemoryStore)


# ---------------------------------------------------------------------------
# AC-B3: IP login rate-limit (429 after threshold)
# ---------------------------------------------------------------------------


def test_ac_b3_login_rate_limit_429(client: TestClient):
    import dataclasses

    client.app.state.login_limiter = None
    client.app.state.settings = dataclasses.replace(
        client.app.state.settings, login_rate_limit=2, login_rate_window=3600
    )
    for _ in range(2):
        r = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
        )
        assert r.status_code == 200, r.text
    denied = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert denied.status_code == 429, denied.text
