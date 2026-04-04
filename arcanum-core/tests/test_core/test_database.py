"""Tests for database module."""
import asyncio
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from arcanum.core.database import Database


@pytest_asyncio.fixture
async def db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        database = Database(db_path)
        await database.connect()
        await database.init_db()
        yield database
        await database.close()


@pytest.mark.asyncio
async def test_session_crud(db):
    # Create
    await db.execute(
        "INSERT INTO sessions (id, name, target, mode) VALUES (?, ?, ?, ?)",
        ("op-test1", "test-op", "example.com", "autopilot"),
    )

    # Read
    row = await db.fetch_one("SELECT * FROM sessions WHERE id = ?", ("op-test1",))
    assert row is not None
    assert row["name"] == "test-op"
    assert row["target"] == "example.com"
    assert row["mode"] == "autopilot"

    # List
    rows = await db.fetch_all("SELECT * FROM sessions")
    assert len(rows) == 1

    # Delete
    await db.execute("DELETE FROM sessions WHERE id = ?", ("op-test1",))
    rows = await db.fetch_all("SELECT * FROM sessions")
    assert len(rows) == 0


@pytest.mark.asyncio
async def test_stash_table(db):
    await db.execute(
        "INSERT INTO stash (id, type, value, note) VALUES (?, ?, ?, ?)",
        ("stash-001", "credential", "admin:pass", "Found in config"),
    )
    row = await db.fetch_one("SELECT * FROM stash WHERE id = ?", ("stash-001",))
    assert row["type"] == "credential"
    assert row["value"] == "admin:pass"
