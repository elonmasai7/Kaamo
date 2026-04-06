from __future__ import annotations

import json
from typing import Any, cast

from redis.asyncio import Redis

from kaamo.config import settings
from kaamo.logging import get_logger

logger = get_logger(__name__)


class RedisQueue:
    def __init__(self, url: str | None = None, queue_name: str | None = None) -> None:
        self._url = url or settings.redis_url
        self._queue_name = queue_name or settings.redis_detection_queue
        self._client: Redis | None = None

    async def connect(self) -> Redis:
        if self._client is None:
            self._client = Redis.from_url(self._url, encoding="utf-8", decode_responses=True)
            await cast(Any, self._client.ping())
            logger.info("db.redis.connected", url=self._url, queue=self._queue_name)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None
            logger.info("db.redis.closed", queue=self._queue_name)

    @property
    def client(self) -> Redis:
        if self._client is None:
            raise RuntimeError("RedisQueue.connect() must be called before accessing the client")
        return self._client

    async def enqueue_detection(self, payload: dict[str, Any]) -> None:
        await cast(Any, self.client.rpush(self._queue_name, json.dumps(payload)))

    async def dequeue_detection(self, timeout_seconds: int = 1) -> dict[str, Any] | None:
        item = await cast(Any, self.client.blpop(self._queue_name, timeout=timeout_seconds))
        if item is None:
            return None
        _, raw_payload = item
        return cast(dict[str, Any], json.loads(raw_payload))
