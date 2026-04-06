from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator

from kaamo.cache.kv_cache import GemmaKVCache
from kaamo.cache.metrics import gemma_inference_duration_seconds, gemma_tokens_per_second
from kaamo.inference.backends.base import InferenceBackend
from kaamo.logging import get_logger

try:
    from llama_cpp import Llama
except ImportError:  # pragma: no cover - optional dependency
    Llama = None

logger = get_logger(__name__)


class LlamaCppBackend(InferenceBackend):
    def __init__(
        self,
        model_path: str,
        n_ctx: int = 8192,
        n_gpu_layers: int = -1,
        n_threads: int = 0,
        model_variant: str = "gemma-3-4b-it",
    ) -> None:
        self._variant = model_variant
        self._backend_name = "cuda" if n_gpu_layers != 0 else "cpu"
        if Llama is None:
            raise RuntimeError("llama-cpp-python is required for local Gemma inference")
        self.llm = Llama(
            model_path=model_path,
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            n_threads=n_threads or os.cpu_count() or 1,
            use_mmap=True,
            use_mlock=True,
            verbose=False,
        )
        self.kv_cache = GemmaKVCache(max_entries=1024)
        self._lock = asyncio.Lock()

    async def generate(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 512,
        temperature: float = 0.0,
        stream: bool = True,
    ) -> AsyncIterator[str]:
        cache_key = self.kv_cache.make_key(messages, temperature=temperature)
        if cached := self.kv_cache.get(cache_key):
            yield cached
            return

        prompt = self._apply_gemma3_template(messages)
        async with self._lock:
            start = time.perf_counter()
            result = ""
            chunks = await asyncio.to_thread(
                self._collect_chunks,
                prompt,
                max_tokens,
                temperature,
                stream,
            )
            for token in chunks:
                result += token
                yield token
            elapsed = max(time.perf_counter() - start, 0.001)
            gemma_inference_duration_seconds.labels(
                variant=self._variant,
                quantization="Q4_K_M",
            ).observe(elapsed)
            gemma_tokens_per_second.labels(
                variant=self._variant,
                quantization="Q4_K_M",
                backend=self._backend_name,
            ).set(len(result.split()) / elapsed)
        self.kv_cache.set(cache_key, result, ttl_s=3600)

    def _collect_chunks(
        self,
        prompt: str,
        max_tokens: int,
        temperature: float,
        stream: bool,
    ) -> list[str]:
        output: list[str] = []
        for chunk in self.llm(prompt, max_tokens=max_tokens, temperature=temperature, stream=stream):
            token = chunk["choices"][0]["text"]
            output.append(token)
        return output

    @staticmethod
    def _apply_gemma3_template(messages: list[dict[str, str]]) -> str:
        parts: list[str] = []
        for msg in messages:
            role = "user" if msg["role"] == "user" else "model"
            parts.append(f"<start_of_turn>{role}\n{msg['content']}<end_of_turn>\n")
        parts.append("<start_of_turn>model\n")
        return "".join(parts)
