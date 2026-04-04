"""CLI command implementations for non-TUI operations."""
import asyncio
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..core.config import get_config
from ..core.database import Database
from ..core.stash import StashManager
from ..core.models import StashType
from ..core.cve_kb import CVEKnowledgeBase
from ..agent.session import SessionManager


console = Console()


async def _get_db() -> Database:
    config = get_config()
    db = Database(config.stash_db.parent / "arcanum.db")
    await db.connect()
    await db.init_db()
    return db


def ops_list():
    """List all operations."""
    async def _run():
        db = await _get_db()
        try:
            rows = await db.fetch_all("SELECT * FROM sessions ORDER BY updated_at DESC")
            if not rows:
                console.print("[yellow]No operations found.[/]")
                return
            table = Table(title="Operations")
            table.add_column("Status", style="bold")
            table.add_column("Name", style="cyan")
            table.add_column("Target")
            table.add_column("Mode")
            table.add_column("Findings", justify="right")
            table.add_column("Updated")
            for row in rows:
                status_icon = "●" if row["status"] == "running" else "○"
                table.add_row(
                    status_icon, row["name"], row["target"] or "",
                    row["mode"], str(row["findings_count"]),
                    row["updated_at"] or "",
                )
            console.print(table)
        finally:
            await db.close()
    asyncio.run(_run())


def ops_new(name: str, target: str = None, mode: str = "manual"):
    """Create a new operation."""
    async def _run():
        db = await _get_db()
        config = get_config()
        try:
            mgr = SessionManager(db)
            session = await mgr.create_session(name=name, target=target, mode=mode)
            # Create workspace directories
            op_dir = config.ops_dir / name
            for subdir in ["workspace/output", "workspace/tools", "workspace/evidence", "findings", "reports"]:
                (op_dir / subdir).mkdir(parents=True, exist_ok=True)
            console.print(f"[green]✓ Operation '{name}' created[/]")
            console.print(f"  Target: {target or 'Not set'}")
            console.print(f"  Mode: {mode}")
            console.print(f"  Workspace: {op_dir}")
        finally:
            await db.close()
    asyncio.run(_run())


def ops_resume(name: str):
    """Resume an operation (launches TUI)."""
    async def _run():
        db = await _get_db()
        try:
            mgr = SessionManager(db)
            session = await mgr.get_session(name)
            if not session:
                console.print(f"[red]Operation '{name}' not found.[/]")
                return
            return session
        finally:
            await db.close()
    session = asyncio.run(_run())
    if session:
        from .app import ArcanumApp
        app = ArcanumApp(mode=session.get("mode", "manual"), target=session.get("target"), op_name=name)
        app.run()


def ops_delete(name: str):
    """Delete an operation."""
    async def _run():
        db = await _get_db()
        try:
            mgr = SessionManager(db)
            deleted = await mgr.delete_session(name)
            if deleted:
                console.print(f"[green]✓ Operation '{name}' deleted[/]")
            else:
                console.print(f"[red]Operation '{name}' not found.[/]")
        finally:
            await db.close()
    asyncio.run(_run())


def stash_list(type_filter: str = None):
    """List stash items."""
    async def _run():
        db = await _get_db()
        try:
            mgr = StashManager(db)
            filter_type = StashType(type_filter) if type_filter else None
            items = await mgr.list(filter_type)
            if not items:
                console.print("[yellow]Stash is empty.[/]")
                return
            table = Table(title="Stash")
            table.add_column("ID", style="dim")
            table.add_column("Type", style="cyan")
            table.add_column("Value")
            table.add_column("Note")
            table.add_column("Created")
            for item in items:
                value = item.value if len(item.value) <= 30 else item.value[:27] + "..."
                # Mask credentials
                item_type = item.type if isinstance(item.type, str) else item.type.value
                if item_type == "credential":
                    parts = value.split(":")
                    if len(parts) >= 2:
                        value = f"{parts[0]}:{'*' * min(len(parts[1]), 8)}"
                table.add_row(item.id, item_type, value, item.note or "", str(item.created_at or ""))
            console.print(table)
        finally:
            await db.close()
    asyncio.run(_run())


def stash_add(type: str, value: str, note: str = None):
    """Add item to stash."""
    async def _run():
        db = await _get_db()
        try:
            mgr = StashManager(db)
            item = await mgr.add(StashType(type), value, note)
            console.print(f"[green]✓ Added to stash: {item.id}[/]")
        finally:
            await db.close()
    asyncio.run(_run())


def stash_pull(item_id: str):
    """Pull stash item into current operation."""
    async def _run():
        db = await _get_db()
        try:
            mgr = StashManager(db)
            item = await mgr.get(item_id)
            if item:
                console.print(f"[green]✓ Pulled: {item.value}[/]")
            else:
                console.print(f"[red]Item '{item_id}' not found.[/]")
        finally:
            await db.close()
    asyncio.run(_run())


def cve_search(query: str):
    """Search CVE knowledge base."""
    async def _run():
        config = get_config()
        kb = CVEKnowledgeBase(config.cve_db)
        await kb.connect()
        try:
            results = await kb.search(query, limit=10)
            if not results:
                console.print(f"[yellow]No CVEs found for: {query}[/]")
                return
            table = Table(title=f"CVE Search: {query}")
            table.add_column("CVE ID", style="cyan bold")
            table.add_column("CVSS", justify="right")
            table.add_column("Description")
            table.add_column("Exploit", justify="center")
            for cve in results:
                score_style = "red" if (cve.cvss_score or 0) >= 9.0 else "yellow" if (cve.cvss_score or 0) >= 7.0 else ""
                table.add_row(
                    cve.id,
                    f"[{score_style}]{cve.cvss_score or 'N/A'}[/]",
                    (cve.description or "")[:80],
                    "Yes" if cve.exploit_available else "No",
                )
            console.print(table)
        finally:
            await kb.close()
    asyncio.run(_run())


def doctor():
    """Check system requirements."""
    import shutil
    import subprocess
    import sys

    console.print(Panel("[bold]Arcanum Core - System Check[/]", style="cyan"))

    checks = [
        ("Python 3.11+", sys.version_info >= (3, 11), f"Python {sys.version}"),
        ("Docker", shutil.which("docker") is not None, shutil.which("docker") or "Not found"),
        ("Ollama", shutil.which("ollama") is not None, shutil.which("ollama") or "Not found"),
    ]

    # Check Docker running
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        docker_running = result.returncode == 0
    except Exception:
        docker_running = False
    checks.append(("Docker Running", docker_running, "Running" if docker_running else "Not running"))

    # Check Ollama running
    try:
        import urllib.request
        req = urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3)
        ollama_running = req.status == 200
    except Exception:
        ollama_running = False
    checks.append(("Ollama Running", ollama_running, "Running" if ollama_running else "Not running"))

    table = Table()
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    all_ok = True
    for name, passed, detail in checks:
        status = "[green]✓ PASS[/]" if passed else "[red]✗ FAIL[/]"
        if not passed:
            all_ok = False
        table.add_row(name, status, detail)

    console.print(table)
    if all_ok:
        console.print("\n[bold green]All checks passed! Ready to go.[/]")
    else:
        console.print("\n[bold yellow]Some checks failed. Install missing requirements.[/]")
