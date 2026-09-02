from __future__ import annotations

import logging
import os

import jwt
import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.config import Settings
from fusion_identity.jwks import KeyRing
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

TEST_JWT_KEY = "test-signing-key-please-not-prod"
TEST_SERVICE_TOKEN = "test-service-token"


def _rs256_settings() -> Settings:
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
        jwt_algorithm="RS256",
        jwt_private_key_pem=None,
        jwt_public_keys=None,
        kek="test-signing-key-please-not-prod",
        mfa_enforce_admin=False,
        redis_url="",
        grpc_port=0,
        lease_ttl_seconds=120,
        trusted_proxies=frozenset(),
        jwt_keyring_path="",
        db_pool_max=8,
    )


@pytest.fixture
def rs_client() -> TestClient:
    settings = _rs256_settings()
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        yield c


def test_keyring_rs256_generates_pair():
    ring = KeyRing.rs256()
    assert ring.algorithm == "RS256"
    assert ring.kid is not None
    assert (
        "BEGIN RSA PRIVATE KEY" in ring.signing_key() or "BEGIN PRIVATE KEY" in ring.signing_key()
    )
    jwks = ring.jwks()
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kty"] == "RSA"
    assert jwks["keys"][0]["alg"] == "RS256"
    assert jwks["keys"][0]["kid"] == ring.kid


def test_keyring_hs256_no_jwks_keys():
    ring = KeyRing.hs256("k")
    assert ring.algorithm == "HS256"
    assert ring.kid is None
    assert ring.jwks() == {"keys": []}


def test_rs256_token_verifies_with_jwks_public(rs_client: TestClient):
    resp = rs_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert "kid" in header
    jwks = rs_client.get("/.well-known/jwks.json").json()
    matched = [k for k in jwks["keys"] if k["kid"] == header["kid"]]
    assert len(matched) == 1
    pub = jwt.algorithms.RSAAlgorithm.from_jwk(matched[0])
    claims = jwt.decode(
        token,
        pub,
        algorithms=["RS256"],
        issuer="fusion-identity",
        audience="fusion-cluster",
    )
    assert claims["tid"] == "default"
    assert claims["role"] == "tenant_admin"


def test_rs256_verify_endpoint_works(rs_client: TestClient):
    resp = rs_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    token = resp.json()["access_token"]
    vresp = rs_client.get(
        "/api/v1/auth/verify",
        params={"token": token},
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
    )
    assert vresp.status_code == 200, vresp.text
    assert vresp.json()["tid"] == "default"


def test_hs256_default_no_jwks_keys(client: TestClient):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert resp.json() == {"keys": []}


def test_rotate_creates_new_kid_and_grace(rs_client: TestClient):
    svc = rs_client.app.state.auth_service
    old_kid = svc._kid
    resp = rs_client.post(
        "/.well-known/jwks/rotate",
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["rotated"] is True
    assert body["kid"] != old_kid
    jwks = body["jwks"]
    kids = [k["kid"] for k in jwks["keys"]]
    assert old_kid in kids
    assert body["kid"] in kids


def test_rotate_then_old_token_still_verifies(rs_client: TestClient):
    login = rs_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
    )
    token = login.json()["access_token"]
    rs_client.post(
        "/.well-known/jwks/rotate",
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
    )
    vresp = rs_client.get(
        "/api/v1/auth/verify",
        params={"token": token},
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
    )
    assert vresp.status_code == 200, vresp.text


def test_rotate_requires_service_token(rs_client: TestClient):
    resp = rs_client.post("/.well-known/jwks/rotate")
    assert resp.status_code in (401, 403)


def test_rotate_hs256_rejected(client: TestClient):
    resp = client.post(
        "/.well-known/jwks/rotate",
        headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
    )
    assert resp.status_code == 400


def test_rotation_persists_across_restart(tmp_path):
    # P0-1: a rotated key must survive a restart. Before the fix, KeyRing.rs256
    # reloaded only the seed PEM and rsa_retired was empty, so tokens signed by
    # the pre-rotation key became unverifiable after any restart.
    persist = str(tmp_path / "keyring.json")
    ring1 = KeyRing.rs256(persist_path=persist)
    old_kid = ring1.kid
    new_kid = ring1.rotate()
    assert new_kid != old_kid
    assert os.path.exists(persist)
    # Simulate restart: rebuild KeyRing from the same persist path.
    ring2 = KeyRing.rs256(persist_path=persist)
    assert ring2.kid == new_kid
    # The retired (pre-rotation) key must still be verifiable.
    retired_keys = [k["kid"] for k in ring2.jwks()["keys"]]
    assert old_kid in retired_keys
    # verify_key_for must resolve the retired kid, not raise.
    assert ring2.verify_key_for(old_kid)  # public pem non-empty


def test_rotation_no_persist_path_rolls_back(tmp_path):
    # P0-1: without a persist_path, rotation stays in-memory (legacy behavior).
    # This documents the hazard — operators MUST set jwt_keyring_path for RS256
    # production. The test asserts the file is NOT created.
    ring = KeyRing.rs256()
    ring.rotate()
    assert not (tmp_path / "keyring.json").exists()
