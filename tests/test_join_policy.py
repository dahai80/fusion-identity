from __future__ import annotations

import dataclasses

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from tests.conftest import TEST_SERVICE_TOKEN, _settings

_SVC = {"Authorization": f"Bearer {TEST_SERVICE_TOKEN}", "X-Tenant-Id": "_system"}


@pytest.fixture
def jc(monkeypatch):
    # verification OFF so test users get bearer tokens at signup directly.
    s = dataclasses.replace(_settings(), email_verification_required=False)
    with TestClient(build_app(s)) as c:
        yield c


def _login(c, username, password, tid):
    r = c.post(
        "/api/v1/auth/login", json={"username": username, "password": password, "tenant_id": tid}
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _h(token, tid):
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": tid}


def _admin(c):
    return _login(c, "admin", "adminpass", "default")


def _mk_tenant(c, tid, join_policy=None):
    # Provision with a seed admin so the caller holds tenant_admin OF THIS
    # tenant (require_tenant_admin_of correctly blocks cross-tenant admin —
    # the bootstrap admin belongs to `default` only).
    body = {
        "tenant_id": tid,
        "display_name": tid.title(),
        "plan": "free",
        "seed_admin": {"username": f"{tid}admin", "password": "Password123456"},
    }
    if join_policy:
        body["join_policy"] = join_policy
    r = c.post("/api/v1/admin/tenants/provision", json=body, headers=_SVC)
    assert r.status_code == 201, r.text
    return _login(c, f"{tid}admin", "Password123456", tid)


def _user(c, username):
    r = c.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "Password123", "email": f"{username}@x.io"},
    )
    assert r.status_code == 201, r.text
    return _login(c, username, "Password123", "community")


def test_default_join_policy_is_invite(jc):
    token = _mk_tenant(jc, "jpdef")
    t = jc.get("/api/v1/tenants/jpdef", headers=_h(token, "jpdef")).json()
    assert t["join_policy"] == "invite"


def test_join_policy_update_and_validation(jc):
    token = _mk_tenant(jc, "jppol")
    r = jc.patch(
        "/api/v1/tenants/jppol",
        json={"join_policy": "open"},
        headers=_h(token, "jppol"),
    )
    assert r.status_code == 200, r.text
    assert r.json()["join_policy"] == "open"
    bad = jc.patch(
        "/api/v1/tenants/jppol", json={"join_policy": "everyone"}, headers=_h(token, "jppol")
    )
    assert bad.status_code == 409
    store = jc.app.state.store
    actions = [a["action"] for a in store._audit if a["tenant_id"] == "jppol"]
    assert "tenant.join_policy_change" in actions


def test_invite_mint_redeem_flow(jc):
    admin = _mk_tenant(jc, "jpinv")
    r = jc.post(
        "/api/v1/tenants/jpinv/invites",
        json={"role": "member"},
        headers=_h(admin, "jpinv"),
    )
    assert r.status_code == 201, r.text
    inv = r.json()
    assert inv["token"].startswith("finv_")
    assert inv["role"] == "member"
    # inventory never leaks the hash
    listed = jc.get("/api/v1/tenants/jpinv/invites", headers=_h(admin, "jpinv")).json()
    assert all("token" not in i and "token_hash" not in i for i in listed)

    user_tok = _user(jc, "invred1")
    red = jc.post(
        "/api/v1/auth/invites/redeem",
        json={"token": inv["token"]},
        headers=_h(user_tok, "community"),
    )
    assert red.status_code == 200, red.text
    assert red.json()["tenant_id"] == "jpinv"
    assert red.json()["role"] == "member"
    # single use
    red2 = jc.post(
        "/api/v1/auth/invites/redeem",
        json={"token": inv["token"]},
        headers=_h(user_tok, "community"),
    )
    assert red2.status_code == 400


def test_invite_invalid_and_expired(jc):
    admin = _mk_tenant(jc, "jpexp")
    user_tok = _user(jc, "invexp1")
    bad = jc.post(
        "/api/v1/auth/invites/redeem",
        json={"token": "finv_" + "x" * 40},
        headers=_h(user_tok, "community"),
    )
    assert bad.status_code == 400
    r = jc.post(
        "/api/v1/tenants/jpexp/invites",
        json={"role": "member", "ttl_seconds": 60},
        headers=_h(admin, "jpexp"),
    )
    token = r.json()["token"]
    # force expiry in the in-memory store
    store = jc.app.state.store
    for rec in store._invites.values():
        rec["expires_at"] = 0
    expired = jc.post(
        "/api/v1/auth/invites/redeem", json={"token": token}, headers=_h(user_tok, "community")
    )
    assert expired.status_code == 400


def test_invite_pre_assigned_role(jc):
    admin = _mk_tenant(jc, "jprole")
    r = jc.post(
        "/api/v1/tenants/jprole/invites",
        json={"role": "operator"},
        headers=_h(admin, "jprole"),
    )
    assert r.status_code == 201, r.text
    user_tok = _user(jc, "invrole1")
    red = jc.post(
        "/api/v1/auth/invites/redeem",
        json={"token": r.json()["token"]},
        headers=_h(user_tok, "community"),
    )
    assert red.status_code == 200
    assert red.json()["role"] == "operator"


def test_self_join_open_policy(jc):
    _mk_tenant(jc, "jpopen", join_policy="open")
    user_tok = _user(jc, "selfjoin1")
    r = jc.post("/api/v1/auth/tenants/jpopen/join", headers=_h(user_tok, "community"))
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "member"
    dup = jc.post("/api/v1/auth/tenants/jpopen/join", headers=_h(user_tok, "community"))
    assert dup.status_code == 409


def test_self_join_rejected_on_non_open(jc):
    _mk_tenant(jc, "jpinv2")
    user_tok = _user(jc, "selfjoin2")
    r = jc.post("/api/v1/auth/tenants/jpinv2/join", headers=_h(user_tok, "community"))
    assert r.status_code == 403


def test_join_request_flow(jc):
    admin = _mk_tenant(jc, "jpappr", join_policy="approval")
    user_tok = _user(jc, "jreq1")
    sub = jc.post(
        "/api/v1/tenants/jpappr/join-requests",
        json={"note": "hi"},
        headers=_h(user_tok, "community"),
    )
    assert sub.status_code == 201, sub.text
    rid = sub.json()["request_id"]
    # duplicate pending → 409
    dup = jc.post("/api/v1/tenants/jpappr/join-requests", headers=_h(user_tok, "community"))
    assert dup.status_code == 409
    # admin sees it pending
    listed = jc.get(
        "/api/v1/tenants/jpappr/join-requests?status=pending", headers=_h(admin, "jpappr")
    ).json()
    assert any(x["request_id"] == rid for x in listed)
    ap = jc.post(f"/api/v1/tenants/jpappr/join-requests/{rid}/approve", headers=_h(admin, "jpappr"))
    assert ap.status_code == 200, ap.text
    # approval IS the grant — member visible in the summary
    summary = jc.get("/api/v1/admin/tenants/jpappr/members/summary", headers=_SVC).json()
    assert summary["total"] >= 1
    again = jc.post(
        f"/api/v1/tenants/jpappr/join-requests/{rid}/approve", headers=_h(admin, "jpappr")
    )
    assert again.status_code == 409


def test_join_request_reject_flow(jc):
    admin = _mk_tenant(jc, "jprep", join_policy="approval")
    user_tok = _user(jc, "jreq2")
    sub = jc.post("/api/v1/tenants/jprep/join-requests", headers=_h(user_tok, "community"))
    assert sub.status_code == 201
    rid = sub.json()["request_id"]
    rj = jc.post(f"/api/v1/tenants/jprep/join-requests/{rid}/reject", headers=_h(admin, "jprep"))
    assert rj.status_code == 200
    assert rj.json()["status"] == "rejected"
    # rejected user may re-apply (new pending row allowed)
    sub2 = jc.post("/api/v1/tenants/jprep/join-requests", headers=_h(user_tok, "community"))
    assert sub2.status_code == 201


def test_join_request_requires_approval_policy(jc):
    _mk_tenant(jc, "jpneg")
    user_tok = _user(jc, "jreq3")
    r = jc.post("/api/v1/tenants/jpneg/join-requests", headers=_h(user_tok, "community"))
    assert r.status_code == 403


def test_join_endpoints_rate_limited(monkeypatch):
    s = dataclasses.replace(
        _settings(), email_verification_required=False, login_rate_limit=2, login_rate_window=60
    )
    with TestClient(build_app(s)) as c:
        tok = _login(c, "admin", "adminpass", "default")
        codes = [
            c.post("/api/v1/auth/tenants/default/join", headers=_h(tok, "default")).status_code
            for _ in range(5)
        ]
        assert 429 in codes


def test_join_audited(jc):
    _mk_tenant(jc, "jpaud", join_policy="open")
    assert (
        jc.get(
            "/api/v1/tenants/jpaud",
            headers=_h(_login(jc, "jpaudadmin", "Password123456", "jpaud"), "jpaud"),
        ).json()["join_policy"]
        == "open"
    )
    user_tok = _user(jc, "jaud1")
    jc.post("/api/v1/auth/tenants/jpaud/join", headers=_h(user_tok, "community"))
    store = jc.app.state.store
    actions = [a["action"] for a in store._audit if a["tenant_id"] == "jpaud"]
    assert "member.self_added" in actions
