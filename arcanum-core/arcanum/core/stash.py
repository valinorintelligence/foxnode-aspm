"""Cross-operation artifact sharing system."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .database import Database
from .models import StashItem, StashType


class StashManager:
    """Manages cross-operation artifact sharing."""

    def __init__(self, db: Database):
        self.db = db

    async def add(self, type: StashType, value: str, note: str = None, session_id: str = None) -> StashItem:
        item_id = f"stash-{uuid.uuid4().hex[:8]}"
        type_str = type.value if isinstance(type, StashType) else type
        await self.db.execute(
            "INSERT INTO stash (id, type, value, note, session_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (item_id, type_str, value, note, session_id, datetime.now(timezone.utc).isoformat()),
        )
        return StashItem(
            id=item_id, type=type_str, value=value, note=note,
            session_id=session_id, created_at=datetime.now(timezone.utc),
        )

    async def list(self, type_filter: StashType = None) -> list[StashItem]:
        if type_filter:
            rows = await self.db.fetch_all(
                "SELECT * FROM stash WHERE type = ? ORDER BY created_at DESC", (type_filter.value,)
            )
        else:
            rows = await self.db.fetch_all("SELECT * FROM stash ORDER BY created_at DESC")
        return [StashItem(**row) for row in rows]

    async def get(self, item_id: str) -> StashItem | None:
        row = await self.db.fetch_one("SELECT * FROM stash WHERE id = ?", (item_id,))
        return StashItem(**row) if row else None

    async def pull(self, item_id: str, target_session_id: str) -> StashItem | None:
        """Pull a stash item into a session context."""
        item = await self.get(item_id)
        if item:
            # Create a reference copy for the target session
            new_id = f"stash-{uuid.uuid4().hex[:8]}"
            await self.db.execute(
                "INSERT INTO stash (id, type, value, note, session_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (new_id, item.type if isinstance(item.type, str) else item.type.value,
                 item.value, f"Pulled from {item_id}: {item.note or ''}", target_session_id,
                 datetime.now(timezone.utc).isoformat()),
            )
            return item
        return None

    async def delete(self, item_id: str) -> bool:
        result = await self.db.execute("DELETE FROM stash WHERE id = ?", (item_id,))
        return True

    async def search(self, query: str) -> list[StashItem]:
        rows = await self.db.fetch_all(
            "SELECT * FROM stash WHERE value LIKE ? OR note LIKE ? ORDER BY created_at DESC",
            (f"%{query}%", f"%{query}%"),
        )
        return [StashItem(**row) for row in rows]
