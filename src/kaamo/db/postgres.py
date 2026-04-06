from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import asyncpg

from kaamo.config import settings
from kaamo.logging import get_logger

logger = get_logger(__name__)


class PostgresDatabase:
    def __init__(self, dsn: str | None = None) -> None:
        self._dsn = dsn or settings.postgres_dsn
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> asyncpg.Pool:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(
                dsn=self._dsn,
                min_size=settings.postgres_min_pool_size,
                max_size=settings.postgres_max_pool_size,
                command_timeout=30,
                init=self._init_connection,
            )
            logger.info("db.postgres.connected", dsn=self._dsn)
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.info("db.postgres.closed")

    async def _init_connection(self, connection: asyncpg.Connection) -> None:
        await connection.set_type_codec(
            "jsonb",
            encoder=lambda value: json.dumps(value),
            decoder=lambda value: json.loads(value),
            schema="pg_catalog",
        )

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("PostgresDatabase.connect() must be called before accessing the pool")
        return self._pool

    @asynccontextmanager
    async def transaction(self) -> Any:
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                yield connection


class MigrationRunner:
    def __init__(self, database: PostgresDatabase, migrations_dir: Path | None = None) -> None:
        self._database = database
        self._migrations_dir = migrations_dir or (Path(__file__).resolve().parents[3] / "migrations")

    async def migrate(self) -> None:
        pool = self._database.pool
        async with pool.acquire() as connection:
            await connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            applied = {
                row["version"]
                for row in await connection.fetch("SELECT version FROM schema_migrations")
            }
            for path in sorted(self._migrations_dir.glob("*.sql")):
                if path.name in applied:
                    continue
                sql = path.read_text(encoding="utf-8")
                async with connection.transaction():
                    await connection.execute(sql)
                    await connection.execute(
                        "INSERT INTO schema_migrations(version) VALUES($1)",
                        path.name,
                    )
                logger.info("db.migration.applied", version=path.name)

