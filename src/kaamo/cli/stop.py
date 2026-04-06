from __future__ import annotations

import typer

from kaamo.audit import write_audit_log

app = typer.Typer()


@app.command()
def stop(agent_id: str) -> None:
    write_audit_log("agent.stop", "cli", agent_id)
    typer.echo(f"Stopped {agent_id}")

