from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class AsyncCache(ABC, Generic[K, V]):
    @abstractmethod
    async def get(self, key: K) -> V | None:
        raise NotImplementedError

    @abstractmethod
    async def set(self, key: K, value: V, ttl_s: int) -> None:
        raise NotImplementedError

    @abstractmethod
    async def delete(self, key: K) -> None:
        raise NotImplementedError

