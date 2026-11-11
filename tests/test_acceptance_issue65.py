from __future__ import annotations

import dataclasses
import logging

from starlette.testclient import TestClient

from fusion_identity.app import build_app
from tests.conftest import TEST_SERVICE_TOKEN, _settings

_SVC_HEADERS = {
    "Authorization": f"Bearer {TEST_SERVICE_TOKEN}",
    "X-Tenant-Id": "_system",
}


def _login(client: TestClient, tenant: str = "default") -> dict:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "adminpass", "tenant_id": tenant},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_logout_invalidates_access_token_on_protected_surface(client: TestClient):
    # FS-B-06 (issue #65): logout immediately invalidates the access token —
    # a protected surface must 401 on the post-logout bearer, not ride out
    # the remaining TTL.
    tokens = _login(client)
    bearer = {
        "Authorization": f"Bearer {tokens['access_token']}",
        "X-Tenant-Id": "default",
    }
    ok = client.get("/api/v1/tenants", headers=bearer)
    assert ok.status_code == 200, ok.text

    out = client.post("/api/v1/auth/logout", json={}, headers=bearer)
    assert out.status_code == 200, out.text
    assert out.json()["logged_out"] is True

    after = client.get("/api/v1/tenants", headers=bearer)
    assert after.status_code == 401, after.text
    # and the verify plane agrees (revocation ledger, not just the dependency)
    v = client.post(
        "/api/v1/auth/verify",
        json={"token": tokens["access_token"]},
        headers=_SVC_HEADERS,
    )
    assert v.status_code == 401, v.text


def test_refresh_rotation_single_use(client: TestClient):
    # Issue #65: refresh rotation is single-use at the HTTP plane — the
    # rotated-away token is dead on replay (family revoked, 401).
    tokens = _login(client)
    rt = tokens["refresh_token"]
    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": rt})
    assert r1.status_code == 200, r1.text
    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": rt})
    assert r2.status_code == 401, r2.text
    # the family is gone: even the NEW refresh token from r1 cannot renew
    r3 = client.post("/api/v1/auth/refresh", json={"refresh_token": r1.json()["refresh_token"]})
    assert r3.status_code == 401, r3.text


def test_register_per_ip_throttle(client: TestClient, caplog):
    # FS-H-04 (issue #65): registration carries a per-IP limit equivalent to
    # the login throttle — rotating USERNAMES from one IP still hits 429,
    # and the deny is logged (mass-registration observable).
    s = dataclasses.replace(_settings(), login_rate_limit=2, login_rate_window=60)
    with TestClient(build_app(s)) as c:
        with caplog.at_level(logging.WARNING, logger="fusion_identity.ratelimit"):
            codes = [
                c.post(
                    "/api/v1/auth/register",
                    json={
                        "username": f"iprl{i}",
                        "password": "Password123",
                        "email": f"iprl{i}@x.io",
                    },
                ).status_code
                for i in range(5)
            ]
        assert 429 in codes
        assert all(code in (201, 429) for code in codes)
        assert any("deny" in r.getMessage() for r in caplog.records)
