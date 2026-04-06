from __future__ import annotations

import json

import typer

from kaamo.config import settings

app = typer.Typer()


@app.command()
def status() -> None:
    typer.echo(
        json.dumps(
            {
                "mode": settings.mode,
                "model_store": str(settings.resolved_model_store),
                "pool_size": settings.gemma_pool_size,
            },
            indent=2,
        )
    )

