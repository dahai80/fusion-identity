from __future__ import annotations

import dataclasses
import logging

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from tests.conftest import TEST_SERVICE_TOKEN, _settings

logger = logging.getLogger(__name__)

_SVC = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"}


@pytest.fixture
def rc(monkeypatch):
    # verification OFF so test users get bearer tokens at signup directly.
    s = dataclasses.replace(_settings(), email_verification_required=False)
    with TestClient(build_app(s)) as c:
        yield c


def _login(c, username, password, tid=None):
    body = {"username": username, "password": password}
    if tid is not None:
        body["tenant_id"] = tid
    return c.post("/api/v1/auth/login", json=body)


def _register(c, username):
    r = c.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "Password123", "email": f"{username}@x.io"},
    )
    assert r.status_code == 201, r.text
    return r.json()["user_id"]


def _provision(c, tid):
    r = c.post(
        "/api/v1/admin/tenants/provision",
        json={
            "tenant_id": tid,
            "display_name": tid.title(),
            "plan": "free",
            "seed_admin": {"username": f"{tid}admin", "password": "Password123456"},
        },
        headers=_SVC,
    )
    assert r.status_code == 201, r.text
    return _login(c, f"{tid}admin", "Password123456", tid).json()["access_token"]


def _add_member(c, tid, admin_tok, username):
    # existing platform user requires the by-proof flow (L21)
    r = c.post(
        f"/api/v1/tenants/{tid}/members/by-proof",
        json={"username": username, "password": "Password123", "role": "member"},
        headers={"Authorization": f"Bearer {admin_tok}", "X-Tenant-Id": tid},
    )
    assert r.status_code in (200, 201), r.text


def test_login_without_tenant_single_membership(rc):
    _register(rc, "reslv1")
    r = _login(rc, "reslv1", "Password123")
    assert r.status_code == 200, r.text
    v = rc.post("/api/v1/auth/verify", json={"token": r.json()["access_token"]}, headers=_SVC)
    assert v.status_code == 200, v.text
    assert v.json()["tid"] == "community"


def test_login_without_tenant_no_membership(rc):
    uid = _register(rc, "reslv2")
    del rc.app.state.store._members[("community", uid)]
    r = _login(rc, "reslv2", "Password123")
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"


def test_login_without_tenant_ambiguous(rc):
    _register(rc, "reslv3")
    tok = _provision(rc, "reslvteam")
    _add_member(rc, "reslvteam", tok, "reslv3")
    amb = _login(rc, "reslv3", "Password123")
    assert amb.status_code == 409, amb.text
    detail = amb.json()["detail"]
    assert detail["error"] == "tenant_ambiguous"
    tids = {t["tenant_id"] for t in detail["tenants"]}
    assert tids == {"community", "reslvteam"}
    assert all(t["display_name"] for t in detail["tenants"])
    logger.info("ambiguous resolution tenants=%s", sorted(tids))


def test_login_without_tenant_ambiguous_requires_password(rc):
    _register(rc, "reslv4")
    tok = _provision(rc, "reslvteam2")
    _add_member(rc, "reslvteam2", tok, "reslv4")
    bad = _login(rc, "reslv4", "WrongPassword")
    assert bad.status_code == 401


def test_explicit_tenant_still_works(rc):
    _register(rc, "reslv5")
    ok = _login(rc, "reslv5", "Password123", "community")
    assert ok.status_code == 200, ok.text


def test_wrong_explicit_tenant_tenant_mismatch(rc):
    _register(rc, "reslv6")
    _provision(rc, "reslvother")
    r = _login(rc, "reslv6", "Password123", "reslvother")
    assert r.status_code == 401
    assert r.json()["detail"] == "tenant_mismatch"


def test_unknown_username_tenant_less_invalid(rc):
    r = _login(rc, "reslv_ghost", "Whatever123")
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"


def test_disabled_tenant_excluded_from_resolution(rc):
    uid = _register(rc, "reslv7")
    store = rc.app.state.store
    store._members[("deadteam", uid)] = {
        "tenant_id": "deadteam",
        "user_id": uid,
        "role": "member",
        "added_by": None,
        "added_at": 0,
        "joined_at": 0,
    }
    store._tenants["deadteam"] = {
        "tenant_id": "deadteam",
        "display_name": "Dead",
        "status": "disabled",
    }
    # only membership is in a disabled tenant → resolution finds nothing active
    del store._members[("community", uid)]
    r = _login(rc, "reslv7", "Password123")
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials"
