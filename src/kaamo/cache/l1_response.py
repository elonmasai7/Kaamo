from __future__ import annotations

from kaamo.cache.kv_cache import GemmaKVCache


class ResponseCache:
    def __init__(self, cache: GemmaKVCache | None = None) -> None:
        self._cache = cache or GemmaKVCache()

    async def get(self, cache_key: str | None) -> str | None:
        return self._cache.get(cache_key)

    async def set(self, cache_key: str | None, value: str, ttl_s: int = 1800) -> None:
        self._cache.set(cache_key, value, ttl_s)

