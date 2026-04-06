from __future__ import annotations

import asyncio
import time

import typer

from kaamo.inference.backends.llamacpp_backend import LlamaCppBackend
from kaamo.models.gemma_manager import resolve_model_path

app = typer.Typer()


@app.command()
def benchmark(model_path: str | None = None, prompt: str = "Explain cache invalidation.") -> None:
    async def _run() -> None:
        resolved_model_path = model_path or str(resolve_model_path())
        backend = LlamaCppBackend(model_path=resolved_model_path)
        started = time.perf_counter()
        tokens = []
        async for token in backend.generate([{"role": "user", "content": prompt}], max_tokens=64):
            tokens.append(token)
        elapsed = max(time.perf_counter() - started, 0.001)
        typer.echo(f"tokens={len(tokens)} elapsed={elapsed:.3f}s tps={len(tokens) / elapsed:.2f}")

    asyncio.run(_run())
