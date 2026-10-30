from __future__ import annotations

from pathlib import Path

from fusion_identity.config import DEFAULT_DATABASE_URL

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_default_database_url_is_fusion_identity():
    # Issue #26 (DB-2): the code default must match the canonical production
    # database. The legacy fusion_tenant default caused a split-brain when an
    # instance started without FUSION_IDENTITY_DATABASE_URL.
    assert DEFAULT_DATABASE_URL == "postgresql://127.0.0.1:5432/fusion_identity"


def test_migrations_never_hard_code_target_database():
    # ALTER DATABASE reaches any database from any connection, so a hard-coded
    # name in a migration either mis-targets (the 0007 bug: GUC default landed
    # on the legacy DB) or fails on a fresh install once that DB is retired.
    # Migrations must resolve the target via current_database() instead.
    for sql in sorted((REPO_ROOT / "migrations").glob("*.sql")):
        body = sql.read_text(encoding="utf-8")
        # Strip line comments — historical notes may quote the old literal.
        code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("--"))
        assert "ALTER DATABASE fusion_" not in code, f"{sql.name} hard-codes the target DB"


def test_bootstrap_files_target_fusion_identity_only():
    # The operator bootstrap path (schema.sql) and the compose stack must not
    # create or connect to the retired fusion_tenant database.
    schema = (REPO_ROOT / "deploy" / "sql" / "schema.sql").read_text(encoding="utf-8")
    assert "CREATE DATABASE fusion_identity" in schema
    assert "\\c fusion_identity" in schema
    compose = (REPO_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "fusion_tenant" not in compose
