from __future__ import annotations

import asyncio

from kaamo.config import settings
from kaamo.inference.router import AgentSession, InferenceRouter


class OfflineBackend:
    async def generate(self, messages, max_tokens=512, temperature=0.0, stream=True):
        del messages, max_tokens, temperature, stream
        yield "offline-response"


def test_offline_end_to_end(monkeypatch) -> None:
    monkeypatch.setattr(settings, "mode", "offline")
    router = InferenceRouter(gemma_backend=OfflineBackend())  # type: ignore[arg-type]
    result = asyncio.run(_collect(router))
    assert "".join(result) == "offline-response"


async def _collect(router: InferenceRouter) -> list[str]:
    return [
        token
        async for token in router.route(
            [{"role": "user", "content": "ping"}],
            32,
            AgentSession("e2e", "tester"),
        )
    ]
