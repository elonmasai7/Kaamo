from __future__ import annotations

import typer

from kaamo.audit import write_audit_log

app = typer.Typer()


@app.command()
def start(agent_id: str) -> None:
    write_audit_log("agent.start", "cli", agent_id)
    typer.echo(f"Started {agent_id}")

