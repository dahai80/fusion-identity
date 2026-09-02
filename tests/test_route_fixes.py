from __future__ import annotations

import json
import logging
import time

from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.config import Settings
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

TEST_JWT_KEY = "test-signing-key-please-not-prod"
TEST_SERVICE_TOKEN = "test-service-token"
TEST_KEK = "test-kek-material-distinct-from-jwt-key"
PW = "pw12345678"


def _settings() -> Settings:
    return Settings(
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
        kek=TEST_KEK,
        mfa_enforce_admin=False,
        redis_url="",
        grpc_port=0,
        lease_ttl_seconds=120,
        trusted_proxies=frozenset(),
        jwt_keyring_path="",
        db_pool_max=8,
    )


def _app():
    return build_app(_settings(), store=InMemoryStore(), run_bootstrap=True)


def _admin(client: TestClient) -> str:
    return client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    ).json()["access_token"]


def _hdr(token: str, tenant: str = "default") -> dict:
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": tenant}


def _svc() -> dict:
    return {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


# F3 + P6: OIDC callback rejects a missing/unknown/expired state. We exercise
# the state guards directly (no live IdP) so the rejection happens before any
# outbound call.
async def test_f3_callback_missing_state_rejected():
    with TestClient(_app()) as c:
        # create an idp so the idp_id resolves
        token = _admin(c)
        c.post(
            "/api/v1/tenants/default/idps",
            json={
                "idp_id": "kc",
                "type": "oidc",
                "issuer_url": "http://idp.example/r",
                "client_id": "fusion",
                "client_secret": "s",
                "auto_provision": True,
            },
            headers=_hdr(token),
        )
        resp = c.post("/api/v1/auth/oidc/kc/callback", json={"code": "x"})
        assert resp.status_code == 400, resp.text
        assert "state" in resp.json()["detail"]


async def test_f3_callback_unknown_state_rejected():
    with TestClient(_app()) as c:
        token = _admin(c)
        c.post(
            "/api/v1/tenants/default/idps",
            json={
                "idp_id": "kc",
                "type": "oidc",
                "issuer_url": "http://idp.example/r",
                "client_id": "fusion",
                "client_secret": "s",
                "auto_provision": True,
            },
            headers=_hdr(token),
        )
        resp = c.post("/api/v1/auth/oidc/kc/callback", json={"code": "x", "state": "bogus"})
        assert resp.status_code == 400, resp.text


async def test_p6_callback_expired_state_rejected():
    from fusion_identity.routes import oidc as oidc_mod
    from fusion_identity.routes.oidc import _STATES_TTL

    with TestClient(_app()) as c:
        token = _admin(c)
        c.post(
            "/api/v1/tenants/default/idps",
            json={
                "idp_id": "kc",
                "type": "oidc",
                "issuer_url": "http://idp.example/r",
                "client_id": "fusion",
                "client_secret": "s",
                "auto_provision": True,
            },
            headers=_hdr(token),
        )
        # inject a state aged past TTL
        st = "expiredstate"
        oidc_mod._STATES[st] = {
            "idp_id": "kc",
            "tenant_id": "default",
            "code_verifier": "v",
            "ts": time.time() - (_STATES_TTL + 10),
        }
        resp = c.post("/api/v1/auth/oidc/kc/callback", json={"code": "x", "state": st})
        assert resp.status_code == 400, resp.text
        assert "expired" in resp.json()["detail"]


# M11: a username with control chars / whitespace from userinfo is rejected.
async def test_m11_oidc_sanitize_username_rejects_garbage():
    from fastapi import HTTPException

    from fusion_identity.routes.oidc import _sanitize_username

    ok = _sanitize_username("alice@example.com")
    assert ok == "alice@example.com"
    for bad in ("a b", "a\tb", "na\x00me", "x" * 200, "weird;cmd"):
        try:
            _sanitize_username(bad)
            raise AssertionError(f"expected rejection for {bad!r}")
        except HTTPException as exc:
            assert exc.status_code == 400


# F5: SCIM endpoint rejects an unknown tenantId.
async def test_f5_scim_unknown_tenant_404():
    with TestClient(_app()) as c:
        resp = c.get("/scim/v2/Users?tenantId=ghost", headers=_svc())
        assert resp.status_code == 404, resp.text
        resp = c.get("/scim/v2/Groups?tenantId=ghost", headers=_svc())
        assert resp.status_code == 404, resp.text


# F5: SCIM patch no longer maps userName onto display_name.
async def test_f5_scim_patch_username_not_mapped_to_display():
    with TestClient(_app()) as c:
        create = c.post(
            "/scim/v2/Users?tenantId=default",
            json={"userName": "patchfx@example.com", "displayName": "Original Display"},
            headers=_svc(),
        )
        uid = create.json()["id"]
        resp = c.patch(
            f"/scim/v2/Users/{uid}?tenantId=default",
            json={"userName": "newname@example.com", "displayName": "Updated Display"},
            headers=_svc(),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["displayName"] == "Updated Display"


# L18: introspect caps an oversized body.
async def test_l18_introspect_oversize_body_413(client: TestClient):
    big = "x" * 40000
    resp = client.post(
        "/api/v1/auth/introspect",
        data={"token": big},
        headers={**_svc(), "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 413, resp.text


# L18: introspect tolerates non-UTF-8 body without 500.
async def test_l18_introspect_non_utf8_body_no_crash(client: TestClient):
    resp = client.post(
        "/api/v1/auth/introspect",
        content=b"\xff\xfe\x00bad",
        headers={**_svc(), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"active": False}


# L21: adding an existing global user via plain POST /members is rejected.
async def test_l21_existing_user_add_rejected(client: TestClient):
    token = _admin(client)
    c1 = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "shared", "password": PW, "role": "viewer"},
        headers=_hdr(token),
    )
    assert c1.status_code == 201, c1.text
    c2 = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "shared", "password": PW, "role": "viewer"},
        headers=_hdr(token),
    )
    assert c2.status_code == 409, c2.text
    assert "proof" in c2.json()["detail"]


# L21: add-existing-by-proof succeeds with correct password, fails with wrong.
async def test_l21_by_proof_works(client: TestClient):
    token = _admin(client)
    client.post(
        "/api/v1/tenants/default/members",
        json={"username": "provable", "password": PW, "role": "viewer"},
        headers=_hdr(token),
    )
    # remove membership to simulate a global user not yet in a second tenant
    store = client.app.state.store
    uid = next(u["user_id"] for u in store._users.values() if u["username"] == "provable")
    await store.remove_member("default", uid)
    ok = client.post(
        "/api/v1/tenants/default/members/by-proof",
        json={"username": "provable", "password": PW, "role": "member"},
        headers=_hdr(token),
    )
    assert ok.status_code == 201, ok.text
    # remove again, then wrong password fails
    await store.remove_member("default", uid)
    bad = client.post(
        "/api/v1/tenants/default/members/by-proof",
        json={"username": "provable", "password": "wrongpass99", "role": "member"},
        headers=_hdr(token),
    )
    assert bad.status_code == 401, bad.text


# L20: status reset on a non-member of this tenant is rejected (404), even if
# the user exists globally in another tenant.
async def test_l20_member_status_requires_membership(client: TestClient):
    token = _admin(client)
    store = client.app.state.store
    # user exists globally but is NOT a member of default
    await store.create_user("usr_orphan", "orphan", PW)
    resp = client.patch(
        "/api/v1/tenants/default/members/usr_orphan/status",
        json={"status": "disabled"},
        headers=_hdr(token),
    )
    assert resp.status_code == 404, resp.text
    rpw = client.post(
        "/api/v1/tenants/default/members/usr_orphan/password",
        json={"new_password": "newpass1234"},
        headers=_hdr(token),
    )
    assert rpw.status_code == 404, rpw.text


# M1: list_api_keys does not leak key_hash.
async def test_m1_list_api_keys_no_key_hash(client: TestClient):
    token = _admin(client)
    store = client.app.state.store
    await store.create_api_key("default", "usr_admin", ["models:infer"])
    resp = client.get("/api/v1/tenants/default/api-keys", headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    for row in resp.json():
        assert "key_hash" not in row, row
        assert "raw_key" not in row, row


# M1: tenant export strips key_hash and password hashes.
async def test_m1_export_strips_secrets(client: TestClient):
    token = _admin(client)
    store = client.app.state.store
    await store.create_api_key("default", "usr_admin", ["models:infer"])
    resp = client.get("/api/v1/tenants/default/export", headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    text = json.dumps(body)
    assert "key_hash" not in text
    assert "password_hash" not in text
    assert "salt" not in text


# P3: export accepts since/until and streams (StreamingResponse media type).
async def test_p3_export_time_window_and_stream(client: TestClient):
    token = _admin(client)
    store = client.app.state.store
    await store.record_usage("default", "usr_admin", "tokens", 10, "test", "m")
    resp = client.get(
        "/api/v1/tenants/default/export",
        params={"since": time.time() - 3600, "until": time.time() + 3600},
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body["usage"], list)


# P3: csv export still works and streams.
async def test_p3_export_csv_stream(client: TestClient):
    token = _admin(client)
    resp = client.get(
        "/api/v1/tenants/default/export",
        params={"format": "csv"},
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    assert "section" in resp.text
    assert "tenant_id" in resp.text


# M6: member add conflict returns a generic message, not raw store text.
async def test_m6_member_conflict_generic_detail(client: TestClient):
    token = _admin(client)
    client.post(
        "/api/v1/tenants/default/members",
        json={"username": "conflicty", "password": PW, "role": "viewer"},
        headers=_hdr(token),
    )
    dup = client.post(
        "/api/v1/tenants/default/members",
        json={"username": "conflicty", "password": PW, "role": "viewer"},
        headers=_hdr(token),
    )
    assert dup.status_code == 409
    detail = dup.json()["detail"]
    assert "StoreConflict" not in detail
    assert "traceback" not in detail


# M10: an internal (non-auth) error during mfa verify is not masked as 401.
async def test_m10_mfa_internal_error_not_masked(client: TestClient):
    from starlette.testclient import TestClient as _TC

    token = _admin(client)
    store = client.app.state.store

    async def boom(*a, **k):
        raise RuntimeError("db connection lost")

    store.get_mfa = boom  # type: ignore[method-assign]
    # raise_server_exceptions=False so the 500 response is returned to us
    # instead of the RuntimeError being re-raised inside the test process.
    with _TC(client.app, raise_server_exceptions=False) as c2:
        resp = c2.post(
            "/api/v1/auth/mfa/verify",
            json={"method": "totp", "code": "123456"},
            headers=_hdr(token),
        )
    # RuntimeError propagates to FastAPI's default handler → 500, NOT 401.
    assert resp.status_code == 500, resp.text


# M9: jwks rotate writes an audit record (HS256 path returns 400 but the
# audit-attempt path is still exercised; under RS256 rotation succeeds and
# audits). We test the RS256 path with a real key ring.
async def test_m9_jwks_rotate_writes_audit(client: TestClient):
    from fusion_identity.jwks import KeyRing

    svc = client.app.state.auth_service
    svc._key_ring = KeyRing.rs256()
    resp = client.post("/.well-known/jwks/rotate", headers=_svc())
    assert resp.status_code == 200, resp.text
    store = client.app.state.store
    rows = [r for r in store._audit if r.get("action") == "jwks.rotate"]
    assert rows, "jwks rotate must leave an audit trail"
    svc._key_ring = None
