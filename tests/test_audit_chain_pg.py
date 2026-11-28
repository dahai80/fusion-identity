from __future__ import annotations

import logging
import os
import uuid

import pytest

from fusion_identity.db import PgStore

logger = logging.getLogger(__name__)

PG_URL = os.environ.get(
    "FUSION_IDENTITY_DATABASE_URL",
    "postgresql://postgres:pgpassword@127.0.0.1:5433/fusion_identity",
)

pytestmark = pytest.mark.integration

# Regression (v0.2.49 prod drill): asyncpg returns jsonb as a raw string, so
# PgStore.verify_audit_chain hashed the STRING detail while append_audit
# hashed the DICT — every tenant chain on PG reported invalid (broken_at on
# the first row). Verify must decode detail back to a dict before hashing.


@pytest.fixture
async def pg_store():
    store = PgStore(PG_URL)
    await store.connect()
    yield store
    await store.close()


async def test_pg_audit_chain_valid_after_appends(pg_store: PgStore):
    tenant = "chainpg_" + uuid.uuid4().hex[:8]
    await pg_store.create_tenant(tenant, "ChainPG")
    try:
        for i in range(3):
            await pg_store.append_audit(
                tenant, "usr_x", None, "member", "test.event", "res", {"n": i, "k": "v"}
            )
        verdict = await pg_store.verify_audit_chain(tenant)
        assert verdict == {"valid": True, "broken_at": None}, verdict

        # Tamper: rewrite one row's action — re-verification must flag it.
        row = (
            await pg_store.fetch(
                "SELECT id FROM audit_log WHERE tenant_id=$1 ORDER BY id LIMIT 1", tenant
            )
        )[0]
        await pg_store.execute("UPDATE audit_log SET action='forged' WHERE id=$1", row["id"])
        verdict = await pg_store.verify_audit_chain(tenant)
        assert verdict["valid"] is False
        assert verdict["broken_at"] == row["id"]
    finally:
        await pg_store.execute("DELETE FROM audit_log WHERE tenant_id=$1", tenant)
        await pg_store.execute("DELETE FROM quotas WHERE tenant_id=$1", tenant)
        await pg_store.execute("DELETE FROM tenants WHERE tenant_id=$1", tenant)
