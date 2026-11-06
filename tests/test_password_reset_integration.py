from __future__ import annotations

import contextlib
import dataclasses
import logging
import os

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.db import PgStore
from tests.conftest import _settings

logger = logging.getLogger(__name__)

PG_URL = os.environ.get(
    "FUSION_IDENTITY_DATABASE_URL",
    "postgresql://postgres:pgpassword@127.0.0.1:5433/fusion_identity",
)

pytestmark = pytest.mark.integration

_CREATED: dict[str, list[str]] = {"users": []}


@pytest.fixture
async def pg_reset():
    store = PgStore(PG_URL)
    await store.connect()
    await store.ensure_schema()
    s = dataclasses.replace(_settings(), email_verification_required=False)
    app = build_app(s, store=store, run_bootstrap=False)
    probe = PgStore(PG_URL)
    await probe.connect()
    with TestClient(app) as c:
        c._probe = probe
        yield c
    for uid in _CREATED["users"]:
        for sql in (
            "DELETE FROM tenant_members WHERE user_id=$1",
            "DELETE FROM refresh_tokens WHERE user_id=$1",
            "DELETE FROM issued_jtis WHERE user_id=$1",
            "DELETE FROM audit_log WHERE user_id=$1",
            "DELETE FROM users WHERE user_id=$1",
        ):
            with contextlib.suppress(Exception):
                await probe.execute(sql, uid)
    await probe.close()


def _register(c, username):
    r = c.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "Password123", "email": f"{username}@x.io"},
    )
    assert r.status_code == 201, r.text
    uid = r.json()["user_id"]
    _CREATED["users"].append(uid)
    return uid


async def test_pg_password_reset_roundtrip(pg_reset):
    # Issue #54 on real Postgres: TIMESTAMPTZ columns, atomic consume UPDATE.
    c = pg_reset
    uid = _register(c, "pgpwreset1")
    captured: dict[str, str] = {}

    async def fake_send(settings, to_email, subject, body):
        captured["body"] = body
        return "sent"

    import fusion_identity.email_sender as es

    es.send_email = fake_send
    r = c.post("/api/v1/auth/password/forgot", json={"email": "pgpwreset1@x.io"})
    assert r.status_code == 200 and r.json() == {"sent": True}
    r = c.post("/api/v1/auth/password/forgot", json={"email": "pgpwreset1@x.io"})
    assert r.status_code == 200 and r.json() == {"sent": True}
    # Case-insensitive lookup (issue #53): different case still resolves.
    # Re-arms the token — everything below reads the latest state.
    r2 = c.post("/api/v1/auth/password/forgot", json={"email": "PGPWRESET1@X.IO"})
    assert r2.status_code == 200
    row = await c._probe.fetchrow(
        "SELECT password_reset_token_hash FROM users WHERE user_id=$1", uid
    )
    assert row is not None and row["password_reset_token_hash"]
    # Raw token never stored — only its sha256.
    token_hash = row["password_reset_token_hash"]
    for ln in captured["body"].splitlines():
        if "reset?token=" in ln:
            raw = ln.split("token=")[1].strip()
            break
    import hashlib

    assert hashlib.sha256(raw.encode()).hexdigest() == token_hash

    r = c.post("/api/v1/auth/password/reset", json={"token": raw, "new_password": "NewPass12345"})
    assert r.status_code == 200, r.text
    # Columns cleared on success.
    row = await c._probe.fetchrow(
        "SELECT password_reset_token_hash, password_reset_expires FROM users WHERE user_id=$1",
        uid,
    )
    assert row["password_reset_token_hash"] is None
    assert row["password_reset_expires"] is None
    # New password logs in; old one does not.
    r = c.post(
        "/api/v1/auth/login",
        json={"username": "pgpwreset1", "password": "NewPass12345", "tenant_id": "community"},
    )
    assert r.status_code == 200, r.text
    r = c.post(
        "/api/v1/auth/login",
        json={"username": "pgpwreset1", "password": "Password123", "tenant_id": "community"},
    )
    assert r.status_code == 401
    # Replay on PG rejected.
    r = c.post("/api/v1/auth/password/reset", json={"token": raw, "new_password": "NewPass12345"})
    assert r.status_code == 400
    logger.info("pg password reset roundtrip ok uid=%s", uid)


async def test_pg_duplicate_email_conflict(pg_reset):
    # Issue #53 on real Postgres: duplicate email registration is 409, not 500.
    c = pg_reset
    _register(c, "pgdupmail1")
    r = c.post(
        "/api/v1/auth/register",
        json={"username": "pgdupmail2", "password": "Password123", "email": "pgdupmail1@x.io"},
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "email already registered"
    # Case-insensitive on PG too (lower(email) lookup).
    r = c.post(
        "/api/v1/auth/register",
        json={"username": "pgdupmail3", "password": "Password123", "email": "PGDUPMAIL1@X.IO"},
    )
    assert r.status_code == 409, r.text
    logger.info("pg duplicate email conflict ok")
