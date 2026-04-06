from __future__ import annotations

import asyncio

import typer

from kaamo.db.postgres import MigrationRunner, PostgresDatabase


app = typer.Typer()


@app.command("db-migrate")
def db_migrate() -> None:
    async def _run() -> None:
        database = PostgresDatabase()
        await database.connect()
        try:
            await MigrationRunner(database).migrate()
        finally:
            await database.close()
        typer.echo("Database migrations applied.")

    asyncio.run(_run())

