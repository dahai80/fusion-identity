from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


class Migration:
    def __init__(self, version: str, name: str, sql: str) -> None:
        self.version = version
        self.name = name
        self.sql = sql


def load_migrations() -> list[Migration]:
    migrations: list[Migration] = []
    if not MIGRATIONS_DIR.is_dir():
        logger.warning("migrations dir not found: %s", MIGRATIONS_DIR)
        return migrations
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        stem = path.stem
        parts = stem.split("_", 1)
        version = parts[0]
        name = parts[1] if len(parts) > 1 else stem
        migrations.append(Migration(version, name, path.read_text()))
    migrations.sort(key=lambda m: m.version)
    logger.info("migrations: loaded %d files from %s", len(migrations), MIGRATIONS_DIR)
    return migrations


SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


_MIG_LOCK_KEY = 0x4944454E  # "IDEN" — stable advisory-lock constant for identity migrations

# Issue #94: every table must be readable/writable by the application role or
# the login plane 500s in prod (tests run as superuser/owner and cannot catch
# it). The runner grants the standard privilege set after migrations (works
# when the runner runs as superuser or as the owning role) and then PROBES —
# a missing grant fails startup loudly instead of at first login.
APP_ROLE_ENV = "FUSION_IDENTITY_APP_ROLE"
DEFAULT_APP_ROLE = "fusion_identity_app"

_GRANT_SQL = """
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON ALL TABLES IN SCHEMA public TO {role}
"""

_DEFAULT_PRIVS_SQL = """
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON TABLES TO {role}
"""


def _app_role() -> str:
    import os

    role = os.environ.get(APP_ROLE_ENV, DEFAULT_APP_ROLE).strip()
    return role or DEFAULT_APP_ROLE


async def grant_app_role(conn: Any) -> bool:
    # Best-effort: succeeds when the runner runs as superuser or as a role
    # owning the tables; a permission failure is logged as an ERROR with the
    # operator fix — the probe below still fails startup if grants are
    # actually missing.
    role = _app_role()
    exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role)
    if not exists:
        logger.warning("migrations: app role %s does not exist, skip grant", role)
        return False
    try:
        await conn.execute(_GRANT_SQL.format(role=role))
        await conn.execute(_DEFAULT_PRIVS_SQL.format(role=role))
        logger.info("migrations: granted standard table privileges to %s", role)
        return True
    except Exception as exc:
        logger.error(
            "migrations: could not GRANT to %s (%s) — if the privilege probe "
            "fails, run as the table owner: GRANT SELECT, INSERT, UPDATE, DELETE, "
            "REFERENCES ON ALL TABLES IN SCHEMA public TO %s",
            role,
            exc,
            role,
        )
        return False


# Issue #109: REFERENCES added — FK migrations (0026 conversations -> tenants)
# need it; the 4-DML probe missed the class and 500'd the whole login plane.
_PROBE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "REFERENCES")


async def assert_app_role_privileges(conn: Any) -> None:
    # Issue #94 deployment check, tightened by issue #96: fail-closed probe —
    # the app role must hold the full standard privilege set on every
    # non-internal table, otherwise startup aborts. SELECT-only probing is
    # not enough: login also INSERTs (issued_jtis, audit_log), so a table
    # readable but not writable would still 500 the login plane.
    role = _app_role()
    exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role)
    if not exists:
        logger.warning("migrations: app role %s does not exist, probe skipped", role)
        return
    rows = await conn.fetch(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema='public' AND table_type='BASE TABLE' "
        "AND table_name <> 'schema_migrations' ORDER BY table_name"
    )
    missing = []
    for r in rows:
        for priv in _PROBE_PRIVILEGES:
            ok = await conn.fetchval(
                "SELECT has_table_privilege($1, $2, $3)", role, r["table_name"], priv
            )
            if not ok:
                missing.append(f"{r['table_name']}:{priv}")
    if missing:
        raise RuntimeError(
            f"app role {role} lacks privileges on {len(missing)} table/privilege pair(s): "
            f"{', '.join(missing)} — run GRANT SELECT, INSERT, UPDATE, DELETE, "
            f"REFERENCES ON ALL TABLES IN SCHEMA public TO {role} as the table owner "
            f"(issues #94, #96, #109)"
        )
    logger.info("migrations: app role %s privilege probe passed (%d tables)", role, len(rows))


async def run_migrations(pool: Any) -> list[str]:
    # A8: serialize concurrent startup migrations with a session-level advisory
    # lock so two instances do not race the schema_migrations PK insert.
    async with pool.acquire() as conn:
        await conn.execute("SELECT pg_advisory_lock($1)", _MIG_LOCK_KEY)
        try:
            await conn.execute(SCHEMA_VERSION_TABLE)
            applied = {
                r["version"] for r in await conn.fetch("SELECT version FROM schema_migrations")
            }
            done: list[str] = []
            migrations = load_migrations()
            for mig in migrations:
                if mig.version in applied:
                    continue
                logger.info("migration: applying %s %s", mig.version, mig.name)
                async with conn.transaction():
                    await conn.execute(mig.sql)
                    # A8: idempotent insert so a crashed peer does not block re-apply.
                    await conn.execute(
                        "INSERT INTO schema_migrations(version, name) "
                        "VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                        mig.version,
                        mig.name,
                    )
                done.append(mig.version)
                logger.info("migration: applied %s %s", mig.version, mig.name)
            if not done:
                logger.info("migration: no pending migrations (schema current)")
            # Issue #94: grant + probe run on EVERY startup (not just when
            # migrations applied) so an out-of-band DDL change is caught too.
            await grant_app_role(conn)
            await assert_app_role_privileges(conn)
            return done
        finally:
            await conn.execute("SELECT pg_advisory_unlock($1)", _MIG_LOCK_KEY)
