from __future__ import annotations

import asyncio
import itertools
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from enum import IntEnum


class Priority(IntEnum):
    BATCH = 3
    INTERACTIVE = 2
    SYSTEM = 1


@dataclass(slots=True)
class InferenceRequest:
    messages: list[dict[str, str]]
    max_tokens: int
    temperature: float = 0.0


class InferenceQueue:
    def __init__(self, max_depth: int = 500) -> None:
        self._queue: asyncio.PriorityQueue[tuple[int, int, InferenceRequest, asyncio.Future[str]]] = asyncio.PriorityQueue()
        self._counter = itertools.count()
        self._max_depth = max_depth

    async def enqueue(
        self,
        request: InferenceRequest,
        worker: Callable[[InferenceRequest], Awaitable[str]],
        priority: Priority = Priority.INTERACTIVE,
        timeout: float = 30.0,
    ) -> AsyncIterator[str]:
        if self._queue.qsize() >= self._max_depth:
            raise RuntimeError("Inference queue is full")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[str] = loop.create_future()
        await self._queue.put((int(priority), next(self._counter), request, future))
        asyncio.create_task(self._drain_once(worker))
        result = await asyncio.wait_for(future, timeout=timeout)
        yield result

    async def _drain_once(self, worker: Callable[[InferenceRequest], Awaitable[str]]) -> None:
        if self._queue.empty():
            return
        priority, order, request, future = await self._queue.get()
        del priority, order
        try:
            future.set_result(await worker(request))
        except Exception as exc:  # pragma: no cover - passthrough
            future.set_exception(exc)

