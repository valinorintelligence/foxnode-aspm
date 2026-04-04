"""WebSocket handler for real-time streaming."""
from __future__ import annotations

import json
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..core.config import get_config
from ..agent.engine import AgentEngine
from ..agent.tools import ToolExecutor

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active: dict[str, list[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        if session_id not in self.active:
            self.active[session_id] = []
        self.active[session_id].append(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket):
        if session_id in self.active:
            self.active[session_id].remove(websocket)
            if not self.active[session_id]:
                del self.active[session_id]

    async def broadcast(self, session_id: str, message: dict):
        if session_id in self.active:
            data = json.dumps(message)
            for ws in self.active[session_id]:
                try:
                    await ws.send_text(data)
                except Exception:
                    pass


manager = ConnectionManager()


@router.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await manager.connect(session_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "")

            if msg_type == "chat":
                user_input = data.get("content", "")
                # Get or create engine for this session
                app = websocket.app
                engine = app.state.active_engines.get(session_id)

                if not engine:
                    session = await app.state.session_mgr.get_session(session_id)
                    if not session:
                        await websocket.send_json({"type": "error", "message": "Session not found"})
                        continue
                    # Create a basic engine (sandbox/browser setup would be more complex in production)
                    from ..agent.tools import ToolExecutor
                    tool_executor = ToolExecutor(
                        sandbox=None, browser=None,
                        workspace_dir=get_config().ops_dir / session.get("name", "default") / "workspace",
                        db=app.state.db,
                    )
                    engine = AgentEngine(
                        llm=app.state.llm,
                        tool_executor=tool_executor,
                        session=session,
                    )
                    app.state.active_engines[session_id] = engine

                # Stream agent events
                try:
                    async for event in engine.run(user_input):
                        await manager.broadcast(session_id, event)
                except Exception as e:
                    await websocket.send_json({"type": "error", "message": str(e)})

            elif msg_type == "approve":
                # Handle copilot approval
                await manager.broadcast(session_id, {"type": "approved", "content": "Action approved"})

            elif msg_type == "cancel":
                await manager.broadcast(session_id, {"type": "cancelled", "content": "Action cancelled"})

    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)
