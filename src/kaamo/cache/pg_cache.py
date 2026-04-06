from __future__ import annotations

from typing import Any

import asyncpg

from kaamo.logging import get_logger

logger = get_logger(__name__)


class PostgresCache:
    def __init__(self, pool: Any = None) -> None:
        self._pool = pool

    async def fetch_session_messages(self, session_id: str) -> list[dict[str, str]]:
        if self._pool is None:
            logger.debug("pg.cache.stub", session_id=session_id)
            return []
        async with self._pool.acquire() as connection:
            rows = await connection.fetch(
                "SELECT role, content FROM session_messages WHERE session_id = $1 ORDER BY created_at ASC",
                session_id,
            )
        return [{"role": row["role"], "content": row["content"]} for row in rows]
