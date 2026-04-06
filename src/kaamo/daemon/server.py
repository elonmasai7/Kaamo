from __future__ import annotations

from fastapi import FastAPI, WebSocket

from kaamo.config import settings
from kaamo.daemon.session_router import SessionRouter
from kaamo.inference.router import InferenceRouter
from kaamo.logging import configure_logging

configure_logging()
app = FastAPI(title="Kaamo Daemon", version="2.0.0")
session_router = SessionRouter(InferenceRouter())


@app.get("/healthz")
async def healthcheck() -> dict[str, str]:
    return {"status": "ok", "mode": settings.mode}


@app.websocket("/ws/chat")
async def chat_socket(websocket: WebSocket) -> None:
    await websocket.accept()
    payload = await websocket.receive_json()
    messages = payload.get("messages", [])
    async for token in session_router.stream_reply(
        session_id=str(payload.get("session_id", "adhoc")),
        user_id=str(payload.get("user_id", "anonymous")),
        messages=messages,
        max_tokens=int(payload.get("max_tokens", 256)),
    ):
        await websocket.send_text(token)
    await websocket.close()

