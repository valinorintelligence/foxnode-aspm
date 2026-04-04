"""Async SQLite database layer for Arcanum."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import aiosqlite

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    target TEXT,
    mode TEXT DEFAULT 'manual',
    status TEXT DEFAULT 'created',
    scope TEXT,          -- JSON
    progress TEXT,       -- JSON
    assets TEXT,         -- JSON
    findings_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    type TEXT,
    severity TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    affected TEXT,       -- JSON
    evidence TEXT,       -- JSON
    poc TEXT,            -- JSON
    cve_id TEXT,
    cwe_ids TEXT,        -- JSON
    remediation TEXT,
    verified BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS stash (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    note TEXT,
    session_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


class Database:
    """Thin async wrapper around an aiosqlite connection."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------
    # Standalone connect / close
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the database connection (standalone, outside context manager)."""
        if self._conn is None:
            self._conn = await aiosqlite.connect(self.db_path)
            self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA journal_mode=WAL")
            await self._conn.execute("PRAGMA foreign_keys=ON")

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "Database":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    async def init_db(self) -> None:
        """Create tables if they don't already exist."""
        assert self._conn is not None, "Database not connected"
        await self._conn.executescript(_SCHEMA_SQL)
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    async def execute(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> aiosqlite.Cursor:
        """Execute a single SQL statement and commit."""
        assert self._conn is not None, "Database not connected"
        cursor = await self._conn.execute(sql, params)
        await self._conn.commit()
        return cursor

    async def fetch_one(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> dict[str, Any] | None:
        """Return a single row as a dict, or None."""
        assert self._conn is not None, "Database not connected"
        cursor = await self._conn.execute(sql, params)
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    async def fetch_all(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> list[dict[str, Any]]:
        """Return all matching rows as a list of dicts."""
        assert self._conn is not None, "Database not connected"
        cursor = await self._conn.execute(sql, params)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
