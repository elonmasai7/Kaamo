from __future__ import annotations

import typer

from kaamo.models.gemma_manager import detect_best_variant, load_manifest, resolve_model_path, verify_model

app = typer.Typer()


@app.command()
def verify_model_cmd(variant: str = "auto") -> None:
    selected = detect_best_variant() if variant == "auto" else variant
    manifest = load_manifest()
    metadata = manifest.get(selected)
    path = resolve_model_path(selected)
    ok = verify_model(path, metadata.sha256)
    if not ok:
        raise typer.Exit(code=1)
    typer.echo(f"Verified {path}")
