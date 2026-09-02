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


async def ensure_schema_version_table(pool: Any) -> None:
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_VERSION_TABLE)


async def applied_versions(pool: Any) -> set[str]:
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT version FROM schema_migrations")
        return {r["version"] for r in rows}


async def run_migrations(pool: Any) -> list[str]:
    await ensure_schema_version_table(pool)
    done: list[str] = []
    migrations = load_migrations()
    applied = await applied_versions(pool)
    for mig in migrations:
        if mig.version in applied:
            continue
        logger.info("migration: applying %s %s", mig.version, mig.name)
        async with pool.acquire() as conn, conn.transaction():
            await conn.execute(mig.sql)
            await conn.execute(
                "INSERT INTO schema_migrations(version, name) VALUES ($1, $2)",
                mig.version,
                mig.name,
            )
        done.append(mig.version)
        logger.info("migration: applied %s %s", mig.version, mig.name)
    if not done:
        logger.info("migration: no pending migrations (schema current)")
    return done
