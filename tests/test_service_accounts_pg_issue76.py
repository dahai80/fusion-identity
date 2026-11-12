from __future__ import annotations

import contextlib

import pytest

from tests.test_acceptance_issue71 import PG_URL

_TENANT = "pgsvcacct76"


@pytest.fixture
async def sa_pg():
    from fusion_identity.db import PgStore

    store = PgStore(PG_URL)
    await store.connect()
    await store.ensure_schema()
    cleanup = [
        "DELETE FROM audit_log WHERE tenant_id=$1",
        "DELETE FROM service_accounts WHERE tenant_id=$1",
        # Token exchange records ownership (record_issued_jti) — FK to tenants.
        "DELETE FROM issued_jtis WHERE tenant_id=$1",
        "DELETE FROM event_outbox WHERE tenant_id=$1",
        "DELETE FROM usage_ledger WHERE tenant_id=$1",
        "DELETE FROM lease_log WHERE tenant_id=$1",
        "DELETE FROM api_keys WHERE tenant_id=$1",
        "DELETE FROM quotas WHERE tenant_id=$1",
        "DELETE FROM tenant_members WHERE tenant_id=$1",
        "DELETE FROM tenants WHERE tenant_id=$1",
    ]
    for sql in cleanup:
        with contextlib.suppress(Exception):
            await store.execute(sql, _TENANT)
    await store.create_tenant(_TENANT, "Issue 76 Service Accounts")
    yield store
    for sql in cleanup:
        with contextlib.suppress(Exception):
            await store.execute(sql, _TENANT)
    await store.close()


@pytest.mark.integration
async def test_pg_service_account_lifecycle(sa_pg):
    store = sa_pg
    raw, rec = await store.create_service_account(_TENANT, "autotest", ["shell:read"], None)
    assert raw.startswith("fsa_")
    assert rec["status"] == "active"
    # Hash at rest, raw never stored.
    assert rec["cred_hash"] and raw not in str(rec)
    # Cred lookup: active only, touches last_used_at.
    hit = await store.get_service_account_by_cred(rec["cred_hash"])
    assert hit is not None and hit["account_id"] == rec["account_id"]
    assert hit["last_used_at"] is not None
    # jsonb scopes decode to a real list (live regression: raw string split
    # into per-character tokens in the issued JWT scope claim).
    assert hit["scopes"] == ["shell:read"]
    # Unknown hash -> None.
    assert await store.get_service_account_by_cred("deadbeef") is None
    # Revoke: lookup dead, replayed revoke 409-shaped False.
    assert await store.revoke_service_account(rec["account_id"]) is True
    assert await store.revoke_service_account(rec["account_id"]) is False
    assert await store.get_service_account_by_cred(rec["cred_hash"]) is None
    # Inventory: no cred_hash column leaves the store.
    rows = await store.list_service_accounts(_TENANT)
    assert len(rows) == 1 and all("cred_hash" not in row for row in rows)


@pytest.mark.integration
async def test_pg_service_token_exchange_and_verify(sa_pg):
    import dataclasses

    from starlette.testclient import TestClient

    from fusion_identity.app import build_app
    from fusion_identity.db import PgStore
    from tests.conftest import TEST_SERVICE_TOKEN, _settings
    from tests.test_acceptance_issue71 import _REDIS_URL

    raw, _rec = await store_create(sa_pg)
    # asyncpg pools are loop-bound: the HTTP app gets its OWN unconnected
    # store (app startup connects it on the TestClient portal loop).
    http_store = PgStore(PG_URL)
    s = dataclasses.replace(
        _settings(), redis_url=_REDIS_URL, grpc_port=0, service_account_ttl_seconds=120
    )
    app = build_app(s, store=http_store, run_bootstrap=False)
    with TestClient(app) as http:
        r = http.post("/api/v1/auth/service-accounts/token", json={"credential": raw})
        assert r.status_code == 200, r.text
        tok = r.json()
        assert tok["token_type"] == "bearer" and tok["expires_in"] == 120
        assert "refresh_token" not in tok
        # Verify plane: service principal passes the human gates (no users
        # row, no membership) with read-only shape.
        r = http.post(
            "/api/v1/auth/verify",
            json={"token": tok["access_token"]},
            headers={"Authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
        )
        assert r.status_code == 200, r.text
        v = r.json()
        assert v["role"] == "service" and v["tid"] == _TENANT
        assert v["write_classes"] == [] and v["allowed_menus"] == []
        assert v["scopes"] == ["shell:read"]


async def store_create(store):
    return await store.create_service_account(_TENANT, "exchange", ["shell:read"], None)
