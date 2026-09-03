from __future__ import annotations

import logging

from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.config import Settings
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

TEST_JWT_KEY = "test-signing-key-please-not-prod"
TEST_SERVICE_TOKEN = "test-service-token"
TEST_KEK = "test-kek-material-distinct-from-jwt-key"
_SVC_HEADERS = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


def _settings(**overrides) -> Settings:
    base = dict(
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
    base.update(overrides)
    return Settings(**base)


# ---------------------------------------------------------------------------
# P3-2: stats() failure must surface distinctly in /metrics (not silent 0)
# ---------------------------------------------------------------------------


def test_p3_2_stats_failure_surfaces_error_gauge():
    # A broken store.stats() used to be swallowed → all gauges 0, which a
    # scraper cannot tell apart from a genuinely empty system. The fix emits a
    # fusion_identity_stats_error gauge (1 on failure) so monitoring raises.
    settings = _settings()
    store = InMemoryStore()

    async def boom(*a, **kw):
        raise RuntimeError("db down")

    store.stats = boom  # type: ignore[method-assign]
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        resp = c.get("/metrics")
    assert resp.status_code == 200, resp.text
    body = resp.text
    assert "fusion_identity_stats_error" in body
    # the error gauge must read 1, not 0
    line = next(raw for raw in body.splitlines() if raw.startswith("fusion_identity_stats_error"))
    assert line.split()[-1] == "1", line


def test_p3_2_stats_ok_error_gauge_zero():
    # healthy store → stats_error gauge reads 0 (baseline parity).
    settings = _settings()
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        resp = c.get("/metrics")
    assert resp.status_code == 200, resp.text
    line = next(
        raw for raw in resp.text.splitlines() if raw.startswith("fusion_identity_stats_error")
    )
    assert line.split()[-1] == "0", line


# ---------------------------------------------------------------------------
# P1-5: dormant legacy-scrypt accounts surfaced via metrics (mechanism done)
# ---------------------------------------------------------------------------


def test_p1_5_legacy_scrypt_count_surfaces_in_metrics():
    # The rehash-on-login mechanism handles active accounts; dormant legacy
    # scrypt users (never log in) keep the fixed salt and are invisible without
    # this gauge. A legacy user in the store → gauge > 0 → operator force-resets.
    settings = _settings()
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        # inject a dormant legacy-scrypt account directly
        store._users["usr_legacy"] = {
            "user_id": "usr_legacy",
            "username": "dormant",
            "password_hash": "deadbeef",
            "password_hash_v": "",
            "salt": "fusion-identity",
            "password_algo": "scrypt",
            "must_change_password": False,
        }
        resp = c.get("/metrics")
    assert resp.status_code == 200, resp.text
    line = next(
        raw
        for raw in resp.text.splitlines()
        if raw.startswith("fusion_identity_legacy_scrypt_users")
    )
    assert line.split()[-1] == "1", line


# ---------------------------------------------------------------------------
# P1-4: Redis-backed login rate-limiter (multi-worker limit parity)
# ---------------------------------------------------------------------------


class _FakeRedisLoginCache:
    """Stand-in for IdentityCache.check_login_rate using an in-process counter
    so the rate-limit wiring (cache present → Redis path) is exercised without
    a live Redis. Mirrors the per-IP + per-username dual-bucket contract."""

    def __init__(self, limit: int):
        self.limit = limit
        self.ip_counts: dict[str, int] = {}
        self.u_counts: dict[str, int] = {}

    async def check_login_rate(self, tenant_id, ip, username, limit, window):
        k = f"{tenant_id}:{ip}"
        if self.ip_counts.get(k, 0) >= limit:
            return False
        self.ip_counts[k] = self.ip_counts.get(k, 0) + 1
        if username:
            uk = f"{tenant_id}:{username.lower()}"
            if self.u_counts.get(uk, 0) >= limit:
                return False
            self.u_counts[uk] = self.u_counts.get(uk, 0) + 1
        return True


def test_p1_4_redis_limiter_denies_after_threshold():
    # With the cache plane active, the configured limit must be the real limit
    # (not N× per worker). A fake cache that mirrors the Redis contract denies
    # the (limit+1)-th attempt with 429.
    settings = _settings(login_rate_limit=2, login_rate_window=60)
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    fake_cache = _FakeRedisLoginCache(limit=2)
    with TestClient(app) as c:
        c.app.state.cache = fake_cache
        bodies = [
            {"username": "admin", "password": "adminpass", "tenant_id": "default"} for _ in range(2)
        ]
        statuses = [c.post("/api/v1/auth/login", json=b).status_code for b in bodies]
        assert all(s == 200 for s in statuses), statuses
        denied = c.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
        )
        assert denied.status_code == 429, denied.text


def test_p1_4_redis_limiter_failopen_on_cache_error():
    # If the redis path raises, login must NOT go down — fail-open on rate
    # state (auth still enforced), falling back to in-memory (limit=0 = open).
    settings = _settings(login_rate_limit=2, login_rate_window=60)
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)

    class BrokenCache:
        async def check_login_rate(self, *a, **kw):
            raise RuntimeError("redis evicted")

    with TestClient(app) as c:
        c.app.state.cache = BrokenCache()
        r = c.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpass", "tenant_id": "default"},
        )
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# P2-2: OIDC states Redis-backed (multi-worker callback parity)
# ---------------------------------------------------------------------------


class _FakeOidcStateCache:
    """In-process stand-in for the Redis OIDC-state store so the multi-worker
    path (put on one app, pop on another) is exercised without live Redis."""

    def __init__(self):
        self.store: dict[str, str] = {}

    async def put_oidc_state(self, state, info, ttl):
        import json as _json

        self.store[state] = _json.dumps(info)

    async def pop_oidc_state(self, state):
        import json as _json

        val = self.store.pop(state, None)
        if val is None:
            return None
        return _json.loads(val)


async def test_p2_2_oidc_state_cross_worker_via_cache():
    # The state is started on one app instance and consumed on another, sharing
    # only the Redis state store. Before the fix the in-memory dict was
    # per-process, so the second app saw "unknown state". With the Redis path
    # the callback resolves.
    settings = _settings()
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    shared_cache = _FakeOidcStateCache()
    with TestClient(app) as c:
        c.app.state.cache = shared_cache
        token = _admin_token(c)
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
            headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": "default"},
        )
        # start login on app c → state lands in the shared cache
        login_resp = c.get("/api/v1/auth/oidc/kc/login", follow_redirects=False)
        assert login_resp.status_code == 302
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]
        assert state in shared_cache.store

    # a SECOND app instance (different process) shares only the cache
    app2 = build_app(settings, store=InMemoryStore(), run_bootstrap=True)
    with TestClient(app2) as c2:
        c2.app.state.cache = shared_cache
        c2.post(
            "/api/v1/tenants/default/idps",
            json={
                "idp_id": "kc",
                "type": "oidc",
                "issuer_url": "http://idp.example/r",
                "client_id": "fusion",
                "client_secret": "s",
                "auto_provision": True,
            },
            headers={"Authorization": f"Bearer {_admin_token(c2)}", "X-Tenant-Id": "default"},
        )
        # state was consumed (popped) → a replay must now be "unknown state",
        # not a silent re-accept. We assert pop semantics directly.
        info = await shared_cache.pop_oidc_state(state)
        assert info is not None
        assert info["idp_id"] == "kc"
        # already consumed
        again = await shared_cache.pop_oidc_state(state)
        assert again is None


def _admin_token(client: TestClient, tenant: str = "default") -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": tenant},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# P2-1: OIDC discovery + id_token verification
# ---------------------------------------------------------------------------


def _p2_1_module():
    import fusion_identity.routes.oidc as oidc_mod

    return oidc_mod


def _patch_async_client_transport(monkeypatch, transport):
    # Force every httpx.AsyncClient created during the test to use the mock
    # transport so _discovery / PyJWKClient hit our handler, not the network.
    import httpx

    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *a, **kw):
        kw["transport"] = transport
        real_init(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def _gen_rsa_jwk():
    # Build a real RS256 keypair + a JWK dict (with kid) the IdP JWKS endpoint
    # would serve, plus a PyJWK object wrapping the public key so the test can
    # stub PyJWKClient.get_signing_key_from_jwt without touching the network.
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
    jwk["kid"] = "test-kid"
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    pyjwk = pyjwt.PyJWK.from_dict(jwk)
    return priv_pem, jwk, pyjwk


def _stub_jwks_client(monkeypatch, pyjwk):
    # PyJWKClient fetches keys via urllib (not httpx), so intercept at the
    # PyJWKClient level: return our prebuilt signing key regardless of uri.
    import jwt as pyjwt

    class _StubClient:
        def __init__(self, *a, **kw):
            pass

        def get_signing_key_from_jwt(self, token):
            return pyjwk

    monkeypatch.setattr(pyjwt, "PyJWKClient", _StubClient)
    # C2: the module-level _JWKS_CLIENTS cache would otherwise bypass the stub
    # (a cached real client from a prior test survives across the random test
    # order). Clear it so the stub is the only path.
    import fusion_identity.routes.oidc as oidc_mod

    monkeypatch.setattr(oidc_mod, "_JWKS_CLIENTS", {})


async def test_p2_1_discovery_resolves_endpoints(monkeypatch):
    # The discovery helper must read /.well-known/openid-configuration and resolve
    # the real token/userinfo/jwks endpoints rather than hardcoding /token /userinfo.
    import httpx

    oidc_mod = _p2_1_module()
    monkeypatch.setattr(oidc_mod, "_DISCOVERY", {})
    doc = {
        "issuer": "http://idp.example/r",
        "authorization_endpoint": "http://idp.example/r/authorize",
        "token_endpoint": "http://idp.example/r/oauth/token",
        "userinfo_endpoint": "http://idp.example/r/oauth/userinfo",
        "jwks_uri": "http://idp.example/r/oauth/jwks",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/.well-known/openid-configuration")
        return httpx.Response(200, json=doc)

    _patch_async_client_transport(monkeypatch, httpx.MockTransport(handler))
    disc = await oidc_mod._discovery("http://idp.example/r")
    assert disc["token_endpoint"] == "http://idp.example/r/oauth/token"
    assert disc["userinfo_endpoint"] == "http://idp.example/r/oauth/userinfo"
    assert disc["jwks_uri"] == "http://idp.example/r/oauth/jwks"


async def test_p2_1_discovery_fallback_on_missing_doc(monkeypatch):
    # Legacy OAuth2 IdP with no discovery doc falls back to constructed paths
    # so existing integrations (which used issuer_url+/token) still resolve.
    import httpx

    oidc_mod = _p2_1_module()
    monkeypatch.setattr(oidc_mod, "_DISCOVERY", {})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    _patch_async_client_transport(monkeypatch, httpx.MockTransport(handler))
    disc = await oidc_mod._discovery("http://idp.example/r")
    assert disc["token_endpoint"] == "http://idp.example/r/token"
    assert disc["userinfo_endpoint"] == "http://idp.example/r/userinfo"


async def test_p2_1_verify_id_token_rejects_bad_nonce(monkeypatch):
    # An id_token whose nonce does not match the login's nonce must be rejected
    # (fail-closed 401) — that is the replay/login-fixation defense.
    import time as _time

    import jwt as pyjwt
    from fastapi import HTTPException

    oidc_mod = _p2_1_module()
    priv_pem, jwk, pyjwk = _gen_rsa_jwk()
    _stub_jwks_client(monkeypatch, pyjwk)
    disc = {"issuer": "http://idp.example/r", "jwks_uri": "http://idp.example/r/oauth/jwks"}
    now = int(_time.time())
    id_token = pyjwt.encode(
        {
            "iss": "http://idp.example/r",
            "aud": "fusion",
            "sub": "usr_123",
            "iat": now,
            "exp": now + 3600,
            "nonce": "WRONG",
        },
        priv_pem,
        algorithm="RS256",
        headers={"kid": jwk["kid"]},
    )
    try:
        await oidc_mod._verify_id_token(id_token, disc, "fusion", "EXPECTED-NONCE")
    except HTTPException as exc:
        assert exc.status_code == 401
        return
    raise AssertionError("bad-nonce id_token was accepted")


async def test_p2_1_verify_id_token_accepts_valid(monkeypatch):
    # A correctly signed id_token with matching iss/aud/nonce/exp passes and
    # returns its claims — the happy path that lets the callback skip userinfo.
    import time as _time

    import jwt as pyjwt

    oidc_mod = _p2_1_module()
    priv_pem, jwk, pyjwk = _gen_rsa_jwk()
    _stub_jwks_client(monkeypatch, pyjwk)
    disc = {"issuer": "http://idp.example/r", "jwks_uri": "http://idp.example/r/oauth/jwks"}
    now = int(_time.time())
    id_token = pyjwt.encode(
        {
            "iss": "http://idp.example/r",
            "aud": "fusion",
            "sub": "usr_123",
            "email": "alice@example.com",
            "iat": now,
            "exp": now + 3600,
            "nonce": "NONCE-XYZ",
        },
        priv_pem,
        algorithm="RS256",
        headers={"kid": jwk["kid"]},
    )
    claims = await oidc_mod._verify_id_token(id_token, disc, "fusion", "NONCE-XYZ")
    assert claims["sub"] == "usr_123"
    assert claims["email"] == "alice@example.com"


# ---------------------------------------------------------------------------
# D2: KEK online rotation — dual-window decrypt + re-encrypt sweep
# ---------------------------------------------------------------------------


_OLD_KEK = "old-kek-material-rotating-out"
_NEW_KEK = "new-kek-material-rotating-in"
_SVC_SYS = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"}


def test_d2_dual_window_decrypt_old_kek_secret():
    # A secret encrypted with the OLD kek must still decrypt after the operator
    # rotates to the NEW kek, as long as kek_prev holds the old key. This is the
    # grace window that keeps MFA/OIDC working mid-rotation without stop-the-world.
    from fusion_identity.crypto import decrypt_secret, encrypt_secret

    blob = encrypt_secret("super-secret", _OLD_KEK)
    # new kek alone fails (wrong key) — but the dual window recovers via prev.
    plain = decrypt_secret(blob, _NEW_KEK, _OLD_KEK)
    assert plain == "super-secret"


def test_d2_dual_window_rejects_when_no_prev():
    # Without a prev kek, an old-key blob must fail closed (CryptoError), never
    # silently return garbage — a rotated-away key with no grace window is a hard
    # stop, which the operator must see as a decrypt failure.
    from fusion_identity.crypto import CryptoError, decrypt_secret, encrypt_secret

    blob = encrypt_secret("super-secret", _OLD_KEK)
    try:
        decrypt_secret(blob, _NEW_KEK, None)
    except CryptoError:
        return
    raise AssertionError("old-key blob decrypted without a prev kek window")


def test_d2_reencrypt_endpoint_migrates_idp_and_mfa():
    # End-to-end: secrets encrypted under the OLD kek are re-encrypted to the NEW
    # kek by the admin sweep. After the sweep, decryption with the NEW kek alone
    # (no prev) succeeds — the secrets no longer depend on the retired key.
    from fusion_identity.crypto import decrypt_secret, encrypt_secret

    settings = _settings(kek=_NEW_KEK, kek_prev=_OLD_KEK)
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        _admin_token(c)
        # seed an IdP whose client_secret is encrypted with the OLD kek (as if
        # created before the rotation). auto_provision so it is a full record.
        old_blob = encrypt_secret("idp-secret-old-ke", _OLD_KEK)
        import asyncio

        asyncio.run(
            store.create_idp(
                "d2_idp",
                "default",
                type="oidc",
                issuer_url="http://idp.d2/r",
                client_id="cid",
                client_secret_enc=old_blob,
                auto_provision=True,
            )
        )
        # seed an MFA factor encrypted with the OLD kek.
        old_mfa = encrypt_secret("mfa-secret-old-ke", _OLD_KEK)
        asyncio.run(store.upsert_mfa("usr_admin", "totp", secret_enc=old_mfa, enabled=True))

        resp = c.post("/api/v1/admin/kek/reencrypt", headers=_SVC_SYS)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["idps"]["migrated"] == 1, body
        assert body["mfa"]["migrated"] == 1, body

    # After the sweep: the stored blobs decrypt with the NEW kek ALONE — the old
    # key is no longer needed. This is the "close the window" guarantee.
    idp = asyncio.run(store.get_idp("d2_idp"))
    assert decrypt_secret(idp["client_secret_enc"], _NEW_KEK) == "idp-secret-old-ke"
    mfa = asyncio.run(store.get_mfa("usr_admin", "totp"))
    assert decrypt_secret(mfa["secret_enc"], _NEW_KEK) == "mfa-secret-old-ke"


def test_d2_reencrypt_rejects_without_prev_window():
    # Calling the sweep with no FUSION_IDENTITY_KEK_PREV configured is a 409 —
    # there is no rotation window active, so a sweep is a no-op that would
    # mislead the operator into thinking secrets were migrated.
    settings = _settings(kek=_NEW_KEK, kek_prev=None)
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        resp = c.post("/api/v1/admin/kek/reencrypt", headers=_SVC_SYS)
        assert resp.status_code == 409, resp.text


# ---------------------------------------------------------------------------
# D3: service_token dual-window rotation — old+new accepted during grace
# ---------------------------------------------------------------------------


_OLD_SVC = "old-service-token-rotating-out-xxxxxxxx"
_NEW_SVC = "new-service-token-rotating-in-yyyyyyyy"


def test_d3_service_token_accepts_prev_during_window():
    # During a rotation, callers still presenting the OLD service token must keep
    # working — the dual window accepts both. A /verify call with the old token
    # succeeds (200), not 401, so callers can be rotated off without a hard cut.
    settings = _settings(service_token=_NEW_SVC, service_token_prev=_OLD_SVC)
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        admin = _admin_token(c)
        # /verify is service-token gated — exercise it with BOTH tokens.
        for tok in (_NEW_SVC, _OLD_SVC):
            resp = c.post(
                "/api/v1/auth/verify",
                headers={"Authorization": f"Bearer {tok}"},
                json={"token": admin},
            )
            assert resp.status_code == 200, f"token {tok[:8]} rejected: {resp.text}"


def test_d3_service_token_rejects_when_window_closed():
    # Once the operator drops SERVICE_TOKEN_PREV, the old token must fail closed
    # (401) — the retired token cannot authenticate, so rotation actually takes
    # effect instead of silently keeping the old token alive forever.
    settings = _settings(service_token=_NEW_SVC, service_token_prev=None)
    store = InMemoryStore()
    app = build_app(settings, store=store, run_bootstrap=True)
    with TestClient(app) as c:
        resp = c.post(
            "/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {_OLD_SVC}"},
            json={"token": "any"},
        )
        assert resp.status_code == 401, resp.text


def test_d3_config_rejects_prev_equal_current(monkeypatch):
    # A prev token equal to the current token is a no-op rotation — load_settings
    # must reject it fail-closed so the operator does not think a window is active
    # when it is not. Validated at the env-load boundary (same place as F9/F16).
    from fusion_identity.config import ConfigError, load_settings

    monkeypatch.setenv("FUSION_IDENTITY_JWT_KEY", TEST_JWT_KEY)
    monkeypatch.setenv("FUSION_IDENTITY_SERVICE_TOKEN", _NEW_SVC)
    monkeypatch.setenv("FUSION_IDENTITY_KEK", TEST_KEK)
    monkeypatch.setenv("FUSION_IDENTITY_SERVICE_TOKEN_PREV", _NEW_SVC)
    monkeypatch.delenv("FUSION_BOOTSTRAP_ADMIN_USER", raising=False)
    monkeypatch.delenv("FUSION_BOOTSTRAP_ADMIN_PASS", raising=False)
    try:
        load_settings()
    except ConfigError:
        return
    raise AssertionError("prev==current service token was accepted by load_settings")
