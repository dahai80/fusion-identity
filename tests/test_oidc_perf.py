from __future__ import annotations

import logging
import time

import httpx
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

TEST_JWT_KEY = "perf-signing-key"
TEST_SERVICE_TOKEN = "perf-service-token"
TEST_KEK = "perf-kek-material"


def _settings():
    from fusion_identity.config import Settings

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


def _gen_rsa():
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk["kid"] = "perf-kid"
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return priv_pem, jwk


def _stub_jwks(monkeypatch, jwk):
    import jwt as pyjwt

    call_count = {"n": 0}

    class _StubClient:
        def __init__(self, *a, **kw):
            call_count["n"] += 1

        def get_signing_key_from_jwt(self, token):
            return pyjwt.PyJWK.from_dict(jwk)

    monkeypatch.setattr(pyjwt, "PyJWKClient", _StubClient)
    return call_count


def _patch_transport(monkeypatch, jwk, priv_pem, cold_delay: float, nonce_holder):
    import time as _time

    import jwt as pyjwt

    doc = {
        "issuer": "http://idp.perf/r",
        "authorization_endpoint": "http://idp.perf/r/authorize",
        "token_endpoint": "http://idp.perf/r/token",
        "userinfo_endpoint": "http://idp.perf/r/userinfo",
        "jwks_uri": "http://idp.perf/r/jwks",
    }
    disc_fetched = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            disc_fetched["n"] += 1
            if disc_fetched["n"] == 1:
                _time.sleep(cold_delay)
            return httpx.Response(200, json=doc)
        if path.endswith("/token"):
            now = int(_time.time())
            id_token = pyjwt.encode(
                {
                    "iss": "http://idp.perf/r",
                    "aud": "fusion",
                    "sub": "usr_perf",
                    "email": "perf@example.com",
                    "iat": now,
                    "exp": now + 3600,
                    "nonce": nonce_holder["v"],
                },
                priv_pem,
                algorithm="RS256",
                headers={"kid": jwk["kid"]},
            )
            return httpx.Response(200, json={"access_token": "at", "id_token": id_token})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *a, **kw):
        kw["transport"] = transport
        real_init(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)
    return disc_fetched


def _admin_token(c, tenant="default"):
    r = c.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": tenant},
    )
    return r.json()["access_token"]


def _seed_idp(c, token):
    c.post(
        "/api/v1/tenants/default/idps",
        json={
            "idp_id": "perf",
            "type": "oidc",
            "issuer_url": "http://idp.perf/r",
            "client_id": "fusion",
            "client_secret": "s",
            "auto_provision": True,
        },
        headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": "default"},
    )


def test_oidc_cold_vs_hot_callback_latency(monkeypatch):
    # P2-1 perf: the first OIDC callback pays discovery (httpx fetch) + first
    # JWKS fetch (PyJWKClient). Discovery is cached on the module, so a second
    # callback reuses it. We assert hot << cold and that discovery is fetched
    # exactly once across two callbacks.
    priv_pem, jwk = _gen_rsa()
    cold_delay = 0.15
    nonce_holder = {"v": ""}
    disc_fetched = _patch_transport(monkeypatch, jwk, priv_pem, cold_delay, nonce_holder)
    jwks_calls = _stub_jwks(monkeypatch, jwk)

    from urllib.parse import parse_qs, urlparse

    import fusion_identity.routes.oidc as oidc_mod

    monkeypatch.setattr(oidc_mod, "_DISCOVERY", {})

    settings = _settings()
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        token = _admin_token(c)
        _seed_idp(c, token)

        login = c.get("/api/v1/auth/oidc/perf/login", follow_redirects=False)
        qs = parse_qs(urlparse(login.headers["location"]).query)
        state = qs["state"][0]
        nonce_holder["v"] = qs["nonce"][0]

        t0 = time.perf_counter()
        cb1 = c.post("/api/v1/auth/oidc/perf/callback", json={"code": "c1", "state": state})
        cold_ms = (time.perf_counter() - t0) * 1000
        assert cb1.status_code == 200, cb1.text

        login2 = c.get("/api/v1/auth/oidc/perf/login", follow_redirects=False)
        qs2 = parse_qs(urlparse(login2.headers["location"]).query)
        state2 = qs2["state"][0]
        nonce_holder["v"] = qs2["nonce"][0]
        t1 = time.perf_counter()
        cb2 = c.post("/api/v1/auth/oidc/perf/callback", json={"code": "c2", "state": state2})
        hot_ms = (time.perf_counter() - t1) * 1000
        assert cb2.status_code == 200, cb2.text

    logger.warning(
        "oidc perf: cold=%.1fms hot=%.1fms discovery_fetches=%s jwks_client_instantiations=%s",
        cold_ms,
        hot_ms,
        disc_fetched["n"],
        jwks_calls["n"],
    )
    assert disc_fetched["n"] == 1, "discovery must be cached after first fetch"
    assert hot_ms < cold_ms, f"hot ({hot_ms:.1f}ms) must be faster than cold ({cold_ms:.1f}ms)"
    # C2: PyJWKClient is cached per jwks_uri, so it is instantiated exactly
    # once across both callbacks (the second reuses the cached client).
    assert jwks_calls["n"] == 1, f"PyJWKClient must be cached, got {jwks_calls['n']} instantiations"
