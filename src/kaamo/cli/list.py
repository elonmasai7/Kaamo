from __future__ import annotations

import json

import typer

from kaamo.config import settings

app = typer.Typer()


@app.command("agents")
def list_agents() -> None:
    agent_dir = settings.home_dir / "agents"
    rows = []
    for path in sorted(agent_dir.glob("*.json")) if agent_dir.exists() else []:
        rows.append(json.loads(path.read_text(encoding="utf-8")))
    typer.echo(json.dumps(rows, indent=2))

