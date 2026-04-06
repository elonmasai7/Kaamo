from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from kaamo.cache.metrics import model_pool_queue_depth, model_pool_wait_seconds
from kaamo.inference.backends.llamacpp_backend import LlamaCppBackend


class ServiceUnavailableError(RuntimeError):
    pass


class GemmaModelPool:
    def __init__(self, model_path: str | Path, pool_size: int) -> None:
        self._pool: asyncio.Queue[LlamaCppBackend] = asyncio.Queue()
        self._size = pool_size
        for _ in range(pool_size):
            self._pool.put_nowait(LlamaCppBackend(str(model_path)))

    @asynccontextmanager
    async def acquire(self, timeout: float = 30.0) -> AsyncIterator[LlamaCppBackend]:
        started = time.perf_counter()
        model_pool_queue_depth.set(self._pool.qsize())
        try:
            instance = await asyncio.wait_for(self._pool.get(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise ServiceUnavailableError("All Gemma instances busy. Retry shortly.") from exc
        waited = time.perf_counter() - started
        model_pool_wait_seconds.observe(waited)
        try:
            yield instance
        finally:
            await self._pool.put(instance)
            model_pool_queue_depth.set(self._pool.qsize())

