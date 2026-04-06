from __future__ import annotations

import typer

from kaamo.cli import benchmark, chat, create, db_migrate, list as list_cmd, logs, pull_model, remove, start, status, stop, token, verify_model

app = typer.Typer(help="Kaamo secure offline-first AI runtime")
app.command(name="create")(create.create)
app.command(name="chat")(chat.chat)
app.command(name="db-migrate")(db_migrate.db_migrate)
app.command(name="start")(start.start)
app.command(name="stop")(stop.stop)
app.command(name="list")(list_cmd.list_agents)
app.command(name="remove")(remove.remove)
app.command(name="logs")(logs.logs)
app.command(name="status")(status.status)
app.command(name="create-token")(token.create_token)
app.command(name="pull-model")(pull_model.pull_model)
app.command(name="verify-model")(verify_model.verify_model_cmd)
app.command(name="benchmark")(benchmark.benchmark)
