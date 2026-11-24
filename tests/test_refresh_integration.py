from __future__ import annotations

import contextlib
import dataclasses
import logging
import os
import uuid

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

# Issue #112: refresh rotation 500'd on PG — rotate set replaced_by (FK to
# refresh_tokens.jti) BEFORE the new row existed. Regression: a full HTTP
# login -> refresh -> refresh chain against PgStore must succeed, and the
# F7 reuse path (replaying a rotated refresh token) must still revoke the
# family.


@pytest.fixture
async def pg_client():
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
    await probe.close()
    await store.close()


async def _purge(probe: PgStore, uid: str) -> None:
    for sql in (
        "DELETE FROM refresh_tokens WHERE user_id=$1",
        "DELETE FROM issued_jtis WHERE user_id=$1",
        "DELETE FROM revoked_jtis WHERE user_id=$1",
        "DELETE FROM tenant_members WHERE user_id=$1",
        "DELETE FROM audit_log WHERE user_id=$1",
        "DELETE FROM users WHERE user_id=$1",
    ):
        with contextlib.suppress(Exception):
            await probe.execute(sql, uid)


async def test_refresh_rotation_chain_pg(pg_client):
    c = pg_client
    probe: PgStore = c._probe
    uid = f"u_{uuid.uuid4().hex[:10]}"
    username = f"rr_{uid}"
    try:
        reg = c.post(
            "/api/v1/auth/register",
            json={"username": username, "password": "Password123"},
        )
        assert reg.status_code == 201, reg.text
        tokens = reg.json()["tokens"]

        # First rotation — this 500'd before the fix (FK violated).
        r1 = c.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert r1.status_code == 200, r1.text
        assert r1.json()["refresh_token"] != tokens["refresh_token"]

        # Second rotation on the rotated token.
        r2 = c.post("/api/v1/auth/refresh", json={"refresh_token": r1.json()["refresh_token"]})
        assert r2.status_code == 200, r2.text

        # F7 reuse: replaying the FIRST refresh token revokes the family.
        r3 = c.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert r3.status_code == 401
        # The chain tip is dead too (family revoked).
        r4 = c.post("/api/v1/auth/refresh", json={"refresh_token": r2.json()["refresh_token"]})
        assert r4.status_code == 401

        rows = await probe.fetch(
            "SELECT status FROM refresh_tokens WHERE user_id=$1", reg.json()["user_id"]
        )
        assert rows and all(r["status"] == "revoked" for r in rows), rows
    finally:
        await _purge(probe, uid)
