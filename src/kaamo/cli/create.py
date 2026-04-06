from __future__ import annotations

import json
from pathlib import Path

import typer

from kaamo.audit import write_audit_log
from kaamo.config import settings

app = typer.Typer()


@app.command()
def create(agent_id: str, image: str = "kaamo/agent-base:latest") -> None:
    agent_dir = settings.home_dir / "agents"
    agent_dir.mkdir(parents=True, exist_ok=True)
    config_path = agent_dir / f"{agent_id}.json"
    config_path.write_text(json.dumps({"agent_id": agent_id, "image": image}, indent=2), encoding="utf-8")
    write_audit_log("agent.config.create", "cli", agent_id, path=str(config_path))
    typer.echo(f"Created {config_path}")

