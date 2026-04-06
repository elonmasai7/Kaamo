from __future__ import annotations

import asyncio

import typer

from kaamo.db.postgres import PostgresDatabase
from kaamo.db.repositories import AuthRepository


app = typer.Typer()


@app.command("create-token")
def create_token(actor: str, role: str = "analyst") -> None:
    async def _run() -> None:
        database = PostgresDatabase()
        await database.connect()
        try:
            repository = AuthRepository(database.pool)
            token_id, token = await repository.create_token(actor=actor, role=role)
        finally:
            await database.close()
        typer.echo(f"token_id={token_id}")
        typer.echo(f"token={token}")

    asyncio.run(_run())

