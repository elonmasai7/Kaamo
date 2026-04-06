from __future__ import annotations

from pathlib import Path

import typer

from kaamo.audit import write_audit_log
from kaamo.config import settings

app = typer.Typer()


@app.command()
def remove(agent_id: str) -> None:
    config_path = settings.home_dir / "agents" / f"{agent_id}.json"
    if config_path.exists():
        config_path.unlink()
    write_audit_log("agent.remove", "cli", agent_id, path=str(config_path))
    typer.echo(f"Removed {agent_id}")

