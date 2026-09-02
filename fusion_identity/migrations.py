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
            return done
        finally:
            await conn.execute("SELECT pg_advisory_unlock($1)", _MIG_LOCK_KEY)
