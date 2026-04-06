from __future__ import annotations

import asyncio

import typer

from kaamo.inference.router import AgentSession, InferenceRouter

app = typer.Typer()


@app.command()
def chat(prompt: str, max_tokens: int = 128) -> None:
    async def _run() -> None:
        router = InferenceRouter()
        session = AgentSession(session_id="cli", user_id="local")
        tokens: list[str] = []
        async for token in router.route(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            session=session,
        ):
            tokens.append(token)
        typer.echo("".join(tokens))

    asyncio.run(_run())

