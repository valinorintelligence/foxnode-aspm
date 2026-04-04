"""Arcanum Core - Autonomous AI-Powered Security Reconnaissance Platform."""

import shutil
import subprocess
import sys

import click


@click.group(invoke_without_command=True)
@click.version_option(version="3.0.0", prog_name="arcanum-core")
@click.pass_context
def main(ctx):
    """Arcanum Core - Autonomous AI-Powered Security Reconnaissance Platform."""
    if ctx.invoked_subcommand is None:
        click.echo("Arcanum Core v3.0.0 - AI Security Recon Platform")
        click.echo("Use --help for available commands, or try: arcanum autopilot <target>")


@main.command()
@click.argument("target")
def autopilot(target: str):
    """Run fully autonomous reconnaissance against a target."""
    from .cli.app import ArcanumApp

    click.echo(f"[AUTOPILOT] Starting full engagement on {target}")
    app = ArcanumApp(mode="autopilot", target=target, op_name=f"auto-{target.replace('.', '-')}")
    app.run()


@main.command()
@click.argument("target")
def copilot(target: str):
    """Run AI-assisted reconnaissance with human oversight."""
    from .cli.app import ArcanumApp

    click.echo(f"[COPILOT] Starting assisted engagement on {target}")
    app = ArcanumApp(mode="copilot", target=target, op_name=f"copilot-{target.replace('.', '-')}")
    app.run()


@main.command()
def manual():
    """Launch the interactive manual TUI."""
    from .cli.app import ArcanumApp

    app = ArcanumApp(mode="manual")
    app.run()


# --- ops group ---


@main.group()
def ops():
    """Manage reconnaissance operations."""


@ops.command("list")
def ops_list_cmd():
    """List all operations."""
    from .cli.commands import ops_list

    ops_list()


@ops.command("new")
@click.argument("name")
@click.option("--target", "-t", default=None, help="Target domain or IP")
@click.option("--mode", "-m", default="manual", type=click.Choice(["autopilot", "copilot", "manual"]))
def ops_new_cmd(name: str, target: str, mode: str):
    """Create a new operation."""
    from .cli.commands import ops_new

    ops_new(name, target, mode)


@ops.command("resume")
@click.argument("name")
def ops_resume_cmd(name: str):
    """Resume a paused operation."""
    from .cli.commands import ops_resume

    ops_resume(name)


@ops.command("delete")
@click.argument("name")
def ops_delete_cmd(name: str):
    """Delete an operation."""
    from .cli.commands import ops_delete

    ops_delete(name)


# --- stash group ---


@main.group()
def stash():
    """Manage cross-operation artifact stash."""


@stash.command("list")
@click.option("--type", "-t", "type_filter", default=None, help="Filter by type")
def stash_list_cmd(type_filter: str):
    """List stashed artifacts."""
    from .cli.commands import stash_list

    stash_list(type_filter)


@stash.command("add")
@click.argument("type")
@click.argument("value")
@click.option("--note", "-n", default=None, help="Note for the item")
def stash_add_cmd(type: str, value: str, note: str):
    """Add an artifact to the stash."""
    from .cli.commands import stash_add

    stash_add(type, value, note)


@stash.command("pull")
@click.argument("item_id")
def stash_pull_cmd(item_id: str):
    """Pull a stash item into current operation."""
    from .cli.commands import stash_pull

    stash_pull(item_id)


# --- cve group ---


@main.group()
def cve():
    """CVE knowledge base operations."""


@cve.command("search")
@click.argument("query")
def cve_search_cmd(query: str):
    """Search the CVE knowledge base."""
    from .cli.commands import cve_search

    cve_search(query)


@cve.command("update")
def cve_update_cmd():
    """Update the local CVE database from NVD."""
    click.echo("Updating CVE database from NVD feeds...")
    click.echo("This may take several minutes for the initial download.")
    # TODO: Implement NVD feed download + import


# --- demo ---


@main.command("demo")
def demo_seed_cmd():
    """Seed demo/mock data for testing without real targets."""
    import asyncio
    from .core.config import get_config
    from .core.database import Database
    from .core.cve_kb import CVEKnowledgeBase
    from .core.demo_data import seed_all_demo_data

    async def _run():
        config = get_config()
        db = Database(config.data_dir / "arcanum.db")
        await db.connect()
        await db.init_db()
        cve_kb = CVEKnowledgeBase(config.cve_db)
        await cve_kb.connect()
        try:
            result = await seed_all_demo_data(db, cve_kb)
            return result
        finally:
            await db.close()
            await cve_kb.close()

    result = asyncio.run(_run())
    if any(v > 0 for v in result.values()):
        click.echo(f"[OK] Demo data seeded:")
        click.echo(f"  Sessions: {result['sessions']}")
        click.echo(f"  Findings: {result['findings']}")
        click.echo(f"  Stash items: {result['stash_items']}")
        click.echo(f"  CVEs: {result['cves']}")
    else:
        click.echo("[INFO] Demo data already exists. Delete ~/.arcanum/arcanum.db to re-seed.")


# --- serve ---


@main.command()
@click.option("--port", "-p", default=8000, help="Port to serve on")
@click.option("--host", "-h", default="0.0.0.0", help="Host to bind to")
def serve(port: int, host: str):
    """Start the web UI server."""
    import uvicorn

    click.echo(f"Starting Arcanum Core Web UI on http://{host}:{port}")
    uvicorn.run("arcanum.api.main:app", host=host, port=port, reload=False)


# --- doctor ---


@main.command()
def doctor():
    """Check system dependencies and environment."""
    from .cli.commands import doctor as run_doctor

    run_doctor()


# --- sandbox group ---


@main.group()
def sandbox():
    """Manage the isolated sandbox environment."""


@sandbox.command("build")
def sandbox_build_cmd():
    """Build the sandbox Docker image."""
    import os

    dockerfile = os.path.join(os.path.dirname(__file__), "..", "docker", "Dockerfile")
    if not os.path.exists(dockerfile):
        click.echo("[ERROR] Dockerfile not found. Run from project root.")
        return
    click.echo("Building Arcanum sandbox image (this may take 10-20 minutes)...")
    result = subprocess.run(
        ["docker", "build", "-t", "arcanum-sandbox:latest", "-f", dockerfile, "."],
        capture_output=False,
    )
    if result.returncode == 0:
        click.echo("[OK] Sandbox image built successfully!")
    else:
        click.echo("[FAIL] Build failed. Check Docker output above.")


if __name__ == "__main__":
    main()
