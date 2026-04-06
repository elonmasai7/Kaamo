from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from kaamo.config import settings
from kaamo.inference.router import AgentSession, InferenceRouter


class DummyBackend:
    def __init__(self, text: str, fail: bool = False) -> None:
        self.text = text
        self.fail = fail
        self.calls = 0

    async def generate(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 512,
        temperature: float = 0.0,
        stream: bool = True,
    ) -> AsyncIterator[str]:
        del messages, max_tokens, temperature, stream
        self.calls += 1
        if self.fail:
            raise RuntimeError("boom")
        yield self.text


def test_offline_mode_uses_gemma(monkeypatch) -> None:
    monkeypatch.setattr(settings, "mode", "offline")
    gemma = DummyBackend("local")
    nvidia = DummyBackend("remote")
    router = InferenceRouter(gemma_backend=gemma, nvidia=nvidia)  # type: ignore[arg-type]
    tokens = asyncio.run(_collect(router, [{"role": "user", "content": "hi"}]))
    assert tokens == ["local"]
    assert gemma.calls == 1
    assert nvidia.calls == 0


def test_hybrid_complex_request_prefers_nvidia(monkeypatch) -> None:
    monkeypatch.setattr(settings, "mode", "hybrid")
    gemma = DummyBackend("local")
    nvidia = DummyBackend("remote")
    router = InferenceRouter(gemma_backend=gemma, nvidia=nvidia)  # type: ignore[arg-type]
    prompt = "analyze " * 600
    tokens = asyncio.run(_collect(router, [{"role": "user", "content": prompt}]))
    assert tokens == ["remote"]
    assert nvidia.calls == 1


async def _collect(router: InferenceRouter, messages: list[dict[str, str]]) -> list[str]:
    return [token async for token in router.route(messages, 32, AgentSession("s", "u"))]
