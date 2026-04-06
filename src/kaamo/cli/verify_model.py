from __future__ import annotations

import typer

from kaamo.models.gemma_manager import GEMMA3_MODELS, MODEL_STORE, detect_best_variant, verify_model

app = typer.Typer()


@app.command()
def verify_model_cmd(variant: str = "auto") -> None:
    selected = detect_best_variant() if variant == "auto" else variant
    metadata = GEMMA3_MODELS[selected]
    path = MODEL_STORE / f"{selected}.gguf"
    ok = verify_model(path, str(metadata["sha256"]))
    if not ok:
        raise typer.Exit(code=1)
    typer.echo(f"Verified {path}")

