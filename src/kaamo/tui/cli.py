from __future__ import annotations

import os
from pathlib import Path

import typer

from kaamo.config import settings
from kaamo.tui.app import KaamoDashboardApp
from kaamo.tui.client import KaamoTuiClient

app = typer.Typer()


@app.command("dashboard")
def dashboard(
    token: str | None = typer.Option(default=None, envvar="KAAMO_API_TOKEN"),
    base_url: str = typer.Option(default=f"http://{settings.api_host}:{settings.api_port}", envvar="KAAMO_API_BASE_URL"),
    uds: Path | None = typer.Option(default=None, envvar="KAAMO_DAEMON_UDS"),
    low_resource: bool = typer.Option(default=False, help="Disable websocket streaming and reduce refresh rate."),
) -> None:
    if token is None:
        raise typer.BadParameter("Provide a bearer token via --token or KAAMO_API_TOKEN")
    resolved_uds = str(uds) if uds is not None else None
    client = KaamoTuiClient(token=token, base_url=base_url, uds_path=resolved_uds)
    KaamoDashboardApp(client=client, low_resource=low_resource).run()
