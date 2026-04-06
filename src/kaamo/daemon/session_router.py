from __future__ import annotations

from collections.abc import AsyncIterator

from kaamo.inference.router import AgentSession, InferenceRouter


class SessionRouter:
    def __init__(self, router: InferenceRouter) -> None:
        self._router = router

    async def stream_reply(
        self,
        session_id: str,
        user_id: str,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> AsyncIterator[str]:
        session = AgentSession(session_id=session_id, user_id=user_id)
        async for token in self._router.route(messages, max_tokens=max_tokens, session=session):
            yield token

