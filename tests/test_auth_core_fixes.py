from __future__ import annotations

import asyncio

import jwt as pyjwt
import pytest
from starlette.testclient import TestClient

from fusion_identity.auth import AuthService
from fusion_identity.store import InMemoryStore
from tests.conftest import TEST_JWT_KEY, TEST_KEK, TEST_SERVICE_TOKEN, _settings


def _login(client: TestClient, tenant: str = "default") -> dict:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": tenant},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _decode(access: str) -> dict:
    return pyjwt.decode(
        access,
        TEST_JWT_KEY,
        algorithms=["HS256"],
        audience="fusion-cluster",
        issuer="fusion-identity",
    )


# F4: cross-tenant jti revoke denied (403)
async def test_f4_cross_tenant_revoke_denied_403(client: TestClient):
    token_a = _login(client, "default")["access_token"]
    store: InMemoryStore = client.app.state.store

    await store.create_tenant("tenantB", "Tenant B", plan="team")
    await store.create_user("usr_b", "userb", "pass-b-12345")
    await store.add_member("tenantB", "usr_b", "tenant_admin")
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "userb", "password": "pass-b-12345", "tenant_id": "tenantB"},
    )
    assert resp.status_code == 200, resp.text
    token_b = resp.json()["access_token"]
    jti_b = _decode(token_b)["jti"]

    revoke = client.post(
        "/api/v1/auth/revoke",
        json={"jti": jti_b},
        headers={"Authorization": f"Bearer {token_a}", "X-Tenant-Id": "default"},
    )
    assert revoke.status_code == 403, revoke.text

    revoke_own = client.post(
        "/api/v1/auth/revoke",
        json={"jti": _decode(token_a)["jti"]},
        headers={"Authorization": f"Bearer {token_a}", "X-Tenant-Id": "default"},
    )
    assert revoke_own.status_code == 200, revoke_own.text


# F6: deleted user's token denied on verify
async def test_f6_deleted_user_token_denied(client: TestClient):
    login = _login(client, "default")
    access = login["access_token"]
    claims = _decode(access)
    store: InMemoryStore = client.app.state.store

    store._users.pop(claims["sub"], None)

    resp = client.get(
        "/api/v1/auth/verify",
        headers={
            "Authorization": f"Bearer {access}",
            "X-Tenant-Id": "default",
            "X-Service-Token": TEST_SERVICE_TOKEN,
        },
    )
    assert resp.status_code == 401, resp.text


# F7: concurrent refresh — second call loses CAS, family revoked, 401
async def test_f7_concurrent_refresh_cas_reuse(client: TestClient):
    login = _login(client, "default")
    refresh = login["refresh_token"]
    svc: AuthService = client.app.state.auth_service
    from fusion_identity.models import RefreshRequest

    results: list = []

    async def _refresh_once() -> None:
        try:
            await svc.refresh(RefreshRequest(refresh_token=refresh))
            results.append("ok")
        except Exception as exc:
            results.append(f"err:{type(exc).__name__}")

    await asyncio.gather(_refresh_once(), _refresh_once())

    assert results.count("ok") == 1, results
    assert any(r.startswith("err") for r in results), results

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await svc.refresh(RefreshRequest(refresh_token=refresh))
    assert exc_info.value.status_code == 401


# F17: rotate() live signing — new kid takes effect without re-snapshot
async def test_f17_rotate_live_signing():
    store = InMemoryStore()
    settings = _settings()

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from fusion_identity.jwks import KeyRing
    from fusion_identity.jwt_utils import issue_token

    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    ring = KeyRing.rs256(priv_pem)
    svc = AuthService(
        store,
        signing_key="unused",
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl=settings.jwt_ttl_seconds,
        refresh_ttl=settings.refresh_ttl_seconds,
        key_ring=ring,
        kek=TEST_KEK,
    )

    kid_before = svc._kid
    access1, _ = issue_token(
        sub="u1",
        tid="default",
        role="tenant_admin",
        scopes=[],
        signing_key=svc._signing_key(),
        issuer=svc._issuer,
        audience=svc._audience,
        ttl_seconds=60,
        token_type="access",
        algorithm=svc._algorithm,
        kid=svc._kid,
    )
    assert access1
    new_kid = ring.rotate()
    assert new_kid is not None
    kid_after = svc._kid
    access2, _ = issue_token(
        sub="u1",
        tid="default",
        role="tenant_admin",
        scopes=[],
        signing_key=svc._signing_key(),
        issuer=svc._issuer,
        audience=svc._audience,
        ttl_seconds=60,
        token_type="access",
        algorithm=svc._algorithm,
        kid=svc._kid,
    )
    assert access2
    assert kid_before is not None
    assert kid_after is not None
    assert kid_before != kid_after


# L10: change_password revokes all existing sessions
async def test_l10_change_password_revokes_sessions(client: TestClient):
    login = _login(client, "default")
    refresh = login["refresh_token"]
    store: InMemoryStore = client.app.state.store
    svc: AuthService = client.app.state.auth_service
    claims = _decode(login["access_token"])

    await svc.change_password(claims["sub"], "adminpass", "newpass-999", tenant_id="default")

    rjti = pyjwt.decode(
        refresh,
        TEST_JWT_KEY,
        algorithms=["HS256"],
        audience="fusion-cluster",
        issuer="fusion-identity",
    )["jti"]
    rt = await store.get_refresh_token(rjti)
    assert rt is not None
    assert rt["status"] == "revoked", rt


# L12: enroll_mfa stores enabled=False
async def test_l12_enroll_mfa_disabled(client: TestClient):
    login = _login(client, "default")
    claims = _decode(login["access_token"])
    svc: AuthService = client.app.state.auth_service

    rec = await svc.enroll_mfa(claims["sub"])
    assert rec["enabled"] is False, rec
    assert rec["method"] == "totp"
    assert rec["secret"]
    assert rec["otpauth_uri"]


# M7: _record_failed_login does not swallow audit failures
async def test_m7_record_failed_login_propagates_audit_error():
    store = InMemoryStore()
    settings = _settings()
    svc = AuthService(
        store,
        signing_key=TEST_JWT_KEY,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl=settings.jwt_ttl_seconds,
        refresh_ttl=settings.refresh_ttl_seconds,
        kek=TEST_KEK,
    )

    async def _boom(*a, **k):
        raise RuntimeError("audit store down")

    store.append_audit = _boom  # type: ignore[assignment]

    user = {"user_id": "u1", "username": "u1", "failed_attempts": 0}

    with pytest.raises(RuntimeError, match="audit store down"):
        await svc._record_failed_login(user, "default")
