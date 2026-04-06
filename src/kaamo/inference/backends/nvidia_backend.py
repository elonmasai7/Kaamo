from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx

from kaamo.config import settings
from kaamo.inference.backends.base import InferenceBackend
from kaamo.inference.circuit_breaker import CircuitBreaker
from kaamo.logging import get_logger
from kaamo.secrets import get_secret

logger = get_logger(__name__)


class NVIDIAAPIError(RuntimeError):
    pass


class NvidiaBackend(InferenceBackend):
    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self._client = client or httpx.AsyncClient(
            base_url=settings.nvidia_api_base_url,
            timeout=settings.nvidia_timeout_seconds,
        )
        self._breaker = circuit_breaker or CircuitBreaker(backend_name="nvidia")

    async def generate(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 512,
        temperature: float = 0.0,
        stream: bool = True,
    ) -> AsyncIterator[str]:
        if not self._breaker.allow_request():
            raise NVIDIAAPIError("NVIDIA circuit breaker is open")
        api_key = get_secret("kaamo", "nvidia")
        if not api_key:
            raise NVIDIAAPIError("NVIDIA API key not configured in keyring")
        payload: dict[str, Any] = {
            "model": "nvidia/llama-3.1-nemotron-ultra-253b-v1",
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": stream,
        }
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            response = await self._client.post("/chat/completions", json=payload, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            raise NVIDIAAPIError("NVIDIA API request failed") from exc
        self._breaker.record_success()
        data = response.json()
        text = data["choices"][0]["message"]["content"]
        yield text

