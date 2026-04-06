from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status

from kaamo.db.repositories import AuthRepository


@dataclass(slots=True)
class AuthenticatedActor:
    token_id: str
    actor: str
    role: str


async def require_authentication(
    request: Request,
    authorization: str | None = Header(default=None),
) -> AuthenticatedActor:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    repo = AuthRepository(request.app.state.postgres.pool)
    principal = await repo.validate_token(token)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
    return AuthenticatedActor(**principal)


async def require_analyst(
    actor: AuthenticatedActor = Depends(require_authentication),
) -> AuthenticatedActor:
    if actor.role not in {"analyst", "admin"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Analyst role required")
    return actor

