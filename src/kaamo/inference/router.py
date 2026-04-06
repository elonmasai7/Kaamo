from __future__ import annotations

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from kaamo.config import settings
from kaamo.inference.backends.llamacpp_backend import LlamaCppBackend
from kaamo.inference.backends.nvidia_backend import NVIDIAAPIError, NvidiaBackend
from kaamo.inference.model_pool import GemmaModelPool
from kaamo.logging import get_logger
from kaamo.models.gemma_manager import resolve_model_path

logger = get_logger(__name__)


@dataclass(slots=True)
class AgentSession:
    session_id: str
    user_id: str


class InferenceRouter:
    def __init__(
        self,
        gemma_pool: GemmaModelPool | None = None,
        nvidia: NvidiaBackend | None = None,
        gemma_backend: LlamaCppBackend | None = None,
    ) -> None:
        self.gemma_pool = gemma_pool
        self.nvidia = nvidia or NvidiaBackend()
        self.gemma = gemma_backend

    async def route(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        session: AgentSession,
        temperature: float = 0.0,
    ) -> AsyncIterator[str]:
        mode = settings.mode
        logger.debug("router.decision.start", mode=mode, session_id=session.session_id)

        if mode == "offline":
            async for token in self._generate_gemma(messages, max_tokens, temperature):
                yield token
            return

        if mode == "online":
            try:
                async for token in self.nvidia.generate(messages, max_tokens, temperature=temperature):
                    yield token
                return
            except (NVIDIAAPIError, httpx.ConnectError):
                logger.warning("nvidia.api.unreachable", fallback="gemma")
                async for token in self._generate_gemma(messages, max_tokens, temperature):
                    yield token
                return

        token_count = self._estimate_tokens(messages)
        task_class = self._classify_task(messages)
        backend = "nvidia" if token_count > 4096 or task_class == "complex" else "gemma"
        logger.debug(
            "router.decision",
            mode=mode,
            backend=backend,
            token_count=token_count,
            task_class=task_class,
        )
        if backend == "nvidia":
            try:
                async for token in self.nvidia.generate(messages, max_tokens, temperature=temperature):
                    yield token
                return
            except (NVIDIAAPIError, httpx.ConnectError):
                logger.warning("nvidia.api.unreachable", fallback="gemma")
        async for token in self._generate_gemma(messages, max_tokens, temperature):
            yield token

    async def _generate_gemma(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
    ) -> AsyncIterator[str]:
        if self.gemma_pool is None:
            if self.gemma is None:
                model_path = resolve_model_path(settings.gemma_model)
                self.gemma = LlamaCppBackend(
                    model_path=str(model_path),
                    n_ctx=settings.gemma_context_length,
                    model_variant=settings.gemma_model,
                )
            async for token in self.gemma.generate(messages, max_tokens, temperature=temperature):
                yield token
            return
        async with self.gemma_pool.acquire(timeout=30.0) as backend:
            async for token in backend.generate(messages, max_tokens, temperature=temperature):
                yield token

    def _estimate_tokens(self, messages: list[dict[str, str]]) -> int:
        total = sum(len(message["content"]) for message in messages)
        return total // 4

    def _classify_task(self, messages: list[dict[str, str]]) -> str:
        joined = "\n".join(message["content"] for message in messages)
        if len(joined.split()) > 500:
            return "complex"
        if re.search(r"\b(analyze|enumerate|reverse engineer|multi-step|exploit)\b", joined, flags=re.IGNORECASE):
            return "complex"
        return "simple"
