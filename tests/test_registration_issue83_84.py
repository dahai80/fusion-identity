from __future__ import annotations

import dataclasses

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.store import InMemoryStore, StoreConflict
from tests.conftest import _settings


async def test_register_duplicate_username_409(client: TestClient):
    body = {"username": "dupu83", "password": "pass-83-83", "email": "dupu83@x.io"}
    r = client.post("/api/v1/auth/register", json=body)
    assert r.status_code == 201, r.text
    r = client.post("/api/v1/auth/register", json=body)
    assert r.status_code == 409
    assert r.json()["detail"] == "username already exists"
    # Case variants are distinct usernames (lookup is exact-match, mirrors PG).
    r = client.post(
        "/api/v1/auth/register",
        json={"username": "DupU83", "password": "pass-83-83", "email": "dupu83b@x.io"},
    )
    assert r.status_code == 201, r.text


async def test_create_user_inmemory_duplicate_username(store: InMemoryStore):
    await store.create_user("u83a", "sameu", "pass-83-83", "a83@x.io")
    with pytest.raises(StoreConflict):
        await store.create_user("u83b", "sameu", "pass-83-83", "b83@x.io")


async def test_duplicate_email_enum_free(client: TestClient, settings):
    # Verification ON (fixture default): duplicate email must return the SAME
    # 201 shape as a fresh signup and persist NOTHING.
    body1 = {"username": "fresh84", "password": "pass-84-84", "email": "enum84@x.io"}
    r1 = client.post("/api/v1/auth/register", json=body1)
    assert r1.status_code == 201, r1.text
    fresh = r1.json()

    body2 = {"username": "second84", "password": "pass-84-84", "email": "ENUM84@x.io"}
    r2 = client.post("/api/v1/auth/register", json=body2)
    assert r2.status_code == 201, r2.text
    # Shape-identical (enum-free): same keys, same status.
    assert set(r2.json()) == set(fresh)
    assert r2.json()["status"] == "verification_required"
    assert r2.json()["email_verified"] is False

    app_store: InMemoryStore = client.app.state.store
    # Nothing persisted for the second attempt: no user, no membership, and
    # the FIRST user's verification token untouched (no email side effect).
    assert await app_store.get_user_by_username("second84") is None
    assert await app_store.get_user_by_email("enum84@x.io") is not None
    first = await app_store.get_user_by_email("enum84@x.io")
    assert first["email_verify_token_hash"] is not None
    members = await app_store.list_members("community")
    assert sum(1 for m in members if m["user_id"] == first["user_id"]) == 1

    # The original account still logs in.
    r = client.post(
        "/api/v1/auth/login",
        json={"username": "fresh84", "password": "pass-84-84", "tenant_id": "community"},
    )
    assert r.status_code == 403  # unverified — but resolves to the ORIGINAL
    assert "email not verified" in r.json()["detail"]


async def test_duplicate_email_verification_off_keeps_409():
    # Verification OFF: the endpoint returns a live token pair for a NEW
    # account — issuing one for an existing account would be a takeover, so
    # the readable 409 stays (documented accepted risk, dev-only mode).
    s = dataclasses.replace(_settings(), email_verification_required=False)
    app = build_app(s, store=InMemoryStore(), run_bootstrap=False)
    with TestClient(app) as c:
        body = {"username": "voff84", "password": "pass-84-84", "email": "voff84@x.io"}
        r = c.post("/api/v1/auth/register", json=body)
        assert r.status_code == 201, r.text
        assert "access_token" in r.json()["tokens"]
        r = c.post(
            "/api/v1/auth/register",
            json={"username": "voff84b", "password": "pass-84-84", "email": "voff84@x.io"},
        )
        assert r.status_code == 409
        assert r.json()["detail"] == "email already registered"
