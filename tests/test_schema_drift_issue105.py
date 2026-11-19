from __future__ import annotations

import re
from pathlib import Path

logger = __import__("logging").getLogger(__name__)

SCHEMA = Path(__file__).resolve().parent.parent / "deploy" / "sql" / "schema.sql"
MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


def _schema_sql() -> str:
    return SCHEMA.read_text()


def test_schema_file_exists_and_declares_generated() -> None:
    text = _schema_sql()
    assert "GENERATED" in text, "schema.sql must keep the generated-file header"
    assert "Issue #105" in text
    assert "DO NOT hand-edit" in text


def test_schema_contains_objects_from_drift_report() -> None:
    # Issue #105: these objects silently vanished from schema.sql once and
    # broke fresh installs; they must never drift out again.
    text = _schema_sql()
    for marker in (
        "audit_seq_seq",
        "CREATE TABLE public.service_accounts",
        "CREATE TABLE public.prepaid_orders",
        "CREATE TABLE public.balance_ledger",
        "users_username_uniq",
        "data_reflow_enabled",
        "join_policy",
        "sso_tickets",
    ):
        assert marker in text, f"schema.sql missing object: {marker}"


def test_schema_seed_data_matches_migrations() -> None:
    # pg_dump --schema-only drops data; the seed block appended at the end of
    # schema.sql must mirror migrations 0001 (roles) and 0010 (plan_templates).
    text = _schema_sql()
    assert "INSERT INTO public.roles" in text, "roles seed missing from schema.sql"
    assert "INSERT INTO public.plan_templates" in text, "plan_templates seed missing"
    migration_0010 = MIGRATIONS / "0010_provisioning.sql"
    plan_rows = re.findall(r"\('(\w+)',\s*'\{", migration_0010.read_text())
    assert plan_rows, "could not parse plan rows from migration 0010"
    for plan in plan_rows:
        assert f"('{plan}'," in text.replace("public.", ""), (
            f"plan template '{plan}' missing from schema.sql seed"
        )


def test_schema_table_count_matches_migrations() -> None:
    # Count CREATE TABLE statements: schema.sql (regenerated dump) must cover
    # every table the migrations create. A table added via a new migration but
    # never regenerated into schema.sql fails here.
    schema_tables = set(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?public\.(\w+)", _schema_sql()))
    migration_tables: set[str] = set()
    for path in sorted(MIGRATIONS.glob("*.sql")):
        found = re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?(?:public\.)?(\w+)", path.read_text())
        migration_tables.update(found)
    missing = migration_tables - schema_tables
    assert not missing, f"tables in migrations but missing from schema.sql: {sorted(missing)}"


def test_schema_rls_policies_match_migrations() -> None:
    schema_policies = set(re.findall(r"CREATE POLICY (\w+) ON (?:public\.)?(\w+)", _schema_sql()))
    migration_policies: set[tuple[str, str]] = set()
    for path in sorted(MIGRATIONS.glob("*.sql")):
        migration_policies.update(
            re.findall(r"CREATE POLICY (\w+) ON (?:public\.)?(\w+)", path.read_text())
        )
    missing = migration_policies - schema_policies
    assert not missing, f"RLS policies in migrations but missing from schema.sql: {sorted(missing)}"
