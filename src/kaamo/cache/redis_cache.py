from __future__ import annotations

import msgpack
from redis.asyncio import Redis
from typing import cast

from kaamo.cache.base import AsyncCache
from kaamo.config import settings


class RedisCache(AsyncCache[str, object]):
    def __init__(self, client: Redis | None = None) -> None:
        self._client = client or Redis.from_url(settings.redis_url, encoding=None, decode_responses=False)

    async def get(self, key: str) -> object | None:
        payload = await self._client.get(key)
        if payload is None:
            return None
        return cast(object, msgpack.unpackb(payload, raw=False))

    async def set(self, key: str, value: object, ttl_s: int) -> None:
        payload = msgpack.packb(value, use_bin_type=True)
        await self._client.set(key, payload, ex=ttl_s)

    async def delete(self, key: str) -> None:
        await self._client.delete(key)
