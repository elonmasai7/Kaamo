from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator


class InferenceBackend(ABC):
    @abstractmethod
    def generate(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 512,
        temperature: float = 0.0,
        stream: bool = True,
    ) -> AsyncIterator[str]:
        raise NotImplementedError
