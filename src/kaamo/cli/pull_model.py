from __future__ import annotations

import asyncio

import typer

from kaamo.models.gemma_manager import detect_best_variant, download_model

app = typer.Typer()


@app.command()
def pull_model(variant: str = "auto") -> None:
    selected = detect_best_variant() if variant == "auto" else variant

    async def _run() -> None:
        path = await download_model(selected)
        typer.echo(f"Downloaded {selected} to {path}")

    asyncio.run(_run())

