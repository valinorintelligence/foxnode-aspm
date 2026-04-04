"""Session management for Arcanum operations with SQLite persistence."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


class SessionManager:
    """Create, retrieve, update, and delete operation sessions (persisted to SQLite)."""

    def __init__(self, db: Any):
        self.db = db

    def _generate_id(self) -> str:
        return f"op-{uuid.uuid4().hex[:12]}"

    async def create_session(
        self,
        name: str,
        target: str = None,
        mode: str = "manual",
        scope: dict = None,
    ) -> dict:
        session_id = self._generate_id()
        now = datetime.now(timezone.utc).isoformat()
        await self.db.execute(
            """INSERT INTO sessions (id, name, target, mode, status, scope, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, name, target, mode, "created", json.dumps(scope) if scope else None, now, now),
        )
        return {
            "id": session_id, "name": name, "target": target,
            "mode": mode, "status": "created", "scope": scope,
            "findings_count": 0, "created_at": now, "updated_at": now,
        }

    async def get_session(self, name: str) -> dict | None:
        row = await self.db.fetch_one("SELECT * FROM sessions WHERE name = ?", (name,))
        if not row:
            # Try by ID
            row = await self.db.fetch_one("SELECT * FROM sessions WHERE id = ?", (name,))
        return dict(row) if row else None

    async def list_sessions(self) -> list[dict]:
        rows = await self.db.fetch_all("SELECT * FROM sessions ORDER BY updated_at DESC")
        return [dict(r) for r in rows]

    async def update_session(self, name: str, **kwargs: Any) -> dict | None:
        session = await self.get_session(name)
        if not session:
            return None
        sets = []
        values = []
        for key, value in kwargs.items():
            if key in ("target", "mode", "status", "scope", "progress", "assets"):
                if key in ("scope", "progress", "assets") and isinstance(value, dict):
                    value = json.dumps(value)
                sets.append(f"{key} = ?")
                values.append(value)
        if sets:
            sets.append("updated_at = ?")
            values.append(datetime.now(timezone.utc).isoformat())
            values.append(session["id"])
            await self.db.execute(
                f"UPDATE sessions SET {', '.join(sets)} WHERE id = ?", tuple(values),
            )
        return await self.get_session(name)

    async def delete_session(self, name: str) -> bool:
        session = await self.get_session(name)
        if not session:
            return False
        await self.db.execute("DELETE FROM findings WHERE session_id = ?", (session["id"],))
        await self.db.execute("DELETE FROM sessions WHERE id = ?", (session["id"],))
        return True

    async def get_session_findings(self, session_id: str) -> list[dict]:
        rows = await self.db.fetch_all(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at DESC", (session_id,),
        )
        return [dict(r) for r in rows]
