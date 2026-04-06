from __future__ import annotations

import typer

app = typer.Typer()


@app.command()
def logs(agent_id: str) -> None:
    typer.echo(f"Logs for {agent_id} are emitted via structured stdout and journalctl.")

