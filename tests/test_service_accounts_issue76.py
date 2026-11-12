from __future__ import annotations

import dataclasses

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.jwt_utils import verify_token
from fusion_identity.store import InMemoryStore
from tests.conftest import TEST_JWT_KEY, TEST_SERVICE_TOKEN, _settings

AUTH = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


def _client(store: InMemoryStore, **overrides):
    s = dataclasses.replace(_settings(), **overrides)
    app = build_app(s, store=store, run_bootstrap=False)
    return TestClient(app), s


async def _seed_tenant(store: InMemoryStore) -> None:
    await store.create_tenant("svc1", display_name="Svc 1")


async def test_service_account_lifecycle_and_exchange():
    store = InMemoryStore()
    await store.connect()
    try:
        await _seed_tenant(store)
        client, s = _client(store)
        with client:
            # Create: raw fsa_ credential returned exactly once.
            r = client.post(
                "/api/v1/admin/tenants/svc1/service-accounts",
                json={"name": "autotest", "scopes": ["shell:read"]},
                headers=AUTH,
            )
            assert r.status_code == 200, r.text
            body = r.json()
            cred = body["credential"]
            assert cred.startswith("fsa_")
            assert body["status"] == "active"
            assert "cred_hash" not in body and body["prefix"].endswith("****")

            # Inventory never carries the hash.
            r = client.get("/api/v1/admin/tenants/svc1/service-accounts", headers=AUTH)
            rows = r.json()
            assert len(rows) == 1 and all(
                "cred_hash" not in row and "credential" not in row for row in rows
            )

            # Exchange: short-TTL access-only service token.
            r = client.post("/api/v1/auth/service-accounts/token", json={"credential": cred})
            assert r.status_code == 200, r.text
            tok = r.json()
            assert tok["token_type"] == "bearer"
            assert tok["expires_in"] == 900
            assert "refresh_token" not in tok
            claims = verify_token(
                tok["access_token"],
                TEST_JWT_KEY,
                s.jwt_issuer,
                s.jwt_audience,
                token_type="access",
                algorithms=["HS256"],
            )
            assert claims["role"] == "service"
            assert claims["tid"] == "svc1"
            assert claims["sub"].startswith("sac_")
            assert claims["scope"] == ["shell:read"]

            # Verify plane: service principal authenticates, read-only shape.
            r = client.post(
                "/api/v1/auth/verify",
                json={"token": tok["access_token"]},
                headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
            )
            assert r.status_code == 200, r.text
            v = r.json()
            assert v["role"] == "service" and v["scopes"] == ["shell:read"]
            assert v["write_classes"] == [] and v["allowed_menus"] == []

            # Revoke: exchange denied afterwards, uniform 401.
            account_id = claims["sub"]
            r = client.delete(
                f"/api/v1/admin/tenants/svc1/service-accounts/{account_id}", headers=AUTH
            )
            assert r.status_code == 200, r.text
            r = client.post("/api/v1/auth/service-accounts/token", json={"credential": cred})
            assert r.status_code == 401
            # Replayed credential with a valid signature is also dead: the
            # resolve path re-checks the account.
            r = client.post(
                "/api/v1/auth/verify",
                json={"token": tok["access_token"]},
                headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
            )
            assert r.status_code == 401
    finally:
        await store.close()


async def test_service_account_bad_credential_and_guards():
    store = InMemoryStore()
    await store.connect()
    try:
        await _seed_tenant(store)
        client, _s = _client(store)
        with client:
            # Unknown credential -> uniform 401 (no enumeration).
            r = client.post("/api/v1/auth/service-accounts/token", json={"credential": "fsa_bogus"})
            assert r.status_code == 401
            # No auth header on admin plane -> 401.
            r = client.post("/api/v1/admin/tenants/svc1/service-accounts", json={"name": "x"})
            assert r.status_code == 401
            # Unknown tenant -> 404.
            r = client.post(
                "/api/v1/admin/tenants/ghost/service-accounts",
                json={"name": "x"},
                headers=AUTH,
            )
            assert r.status_code == 404
            # Revoke unknown account -> 404.
            r = client.delete("/api/v1/admin/tenants/svc1/service-accounts/sac_nope", headers=AUTH)
            assert r.status_code == 404
            # Invalid body -> 422.
            r = client.post("/api/v1/auth/service-accounts/token", json={"credential": ""})
            assert r.status_code == 422
    finally:
        await store.close()


async def test_service_token_audit_visible_as_service():
    store = InMemoryStore()
    await store.connect()
    try:
        await _seed_tenant(store)
        client, _s = _client(store)
        with client:
            r = client.post(
                "/api/v1/admin/tenants/svc1/service-accounts",
                json={"name": "ci", "scopes": []},
                headers=AUTH,
            )
            cred = r.json()["credential"]
            client.post("/api/v1/auth/service-accounts/token", json={"credential": cred})
            # Audit chain carries both events; the token issuance is logged
            # with role "service" (non-human, distinguishable from logins).
            rows = store._audit
            actions = [row["action"] for row in rows]
            assert "svc.created" in actions and "svc.token_issued" in actions
            issued = next(row for row in rows if row["action"] == "svc.token_issued")
            assert issued["role"] == "service"
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_service_principal_survives_human_gates():
    # A service principal has NO users row and NO membership — the shared
    # authorization predicate must validate the account instead, or every
    # bearer-protected route 401s the machine.
    store = InMemoryStore()
    await store.connect()
    try:
        await _seed_tenant(store)
        client, _s = _client(store)
        with client:
            r = client.post(
                "/api/v1/admin/tenants/svc1/service-accounts",
                json={"name": "gate", "scopes": ["audit:read"]},
                headers=AUTH,
            )
            cred = r.json()["credential"]
            tok = client.post(
                "/api/v1/auth/service-accounts/token", json={"credential": cred}
            ).json()["access_token"]
            from fusion_identity.auth import AuthService

            svc = client.app.state.auth_service
            assert isinstance(svc, AuthService)
            claims = await svc.resolve_bearer_claims(f"Bearer {tok}")
            assert claims["role"] == "service"
            assert claims["scope"] == ["audit:read"]
    finally:
        await store.close()
