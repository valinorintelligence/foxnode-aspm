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
@click.option("--year", "-y", default=None, type=int, help="Specific year to fetch (default: current + previous)")
def cve_update_cmd(year: int):
    """Update the local CVE database from NVD API 2.0."""
    import asyncio

    from .core.config import get_config
    from .core.cve_kb import CVEKnowledgeBase, CVEEntry

    async def _run():
        import json
        from datetime import datetime

        config = get_config()
        kb = CVEKnowledgeBase(config.cve_db)
        await kb.connect()

        try:
            years = [year] if year else [datetime.now().year, datetime.now().year - 1]
            total = 0

            for y in years:
                click.echo(f"  Fetching CVEs for {y}...")
                start_idx = 0
                year_count = 0

                while True:
                    url = (
                        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                        f"?pubStartDate={y}-01-01T00:00:00.000"
                        f"&pubEndDate={y}-12-31T23:59:59.999"
                        f"&startIndex={start_idx}&resultsPerPage=200"
                    )
                    try:
                        import httpx
                        async with httpx.AsyncClient(timeout=60) as client:
                            resp = await client.get(url)
                            if resp.status_code == 403:
                                click.echo(f"  Rate limited. Waiting 10s...")
                                import time
                                time.sleep(10)
                                continue
                            resp.raise_for_status()
                            data = resp.json()
                    except Exception as e:
                        click.echo(f"  Error fetching: {e}")
                        break

                    vulns = data.get("vulnerabilities", [])
                    if not vulns:
                        break

                    entries = []
                    for item in vulns:
                        cve_data = item.get("cve", {})
                        cve_id = cve_data.get("id", "")
                        if not cve_id:
                            continue

                        desc = ""
                        for d in cve_data.get("descriptions", []):
                            if d.get("lang") == "en":
                                desc = d.get("value", "")
                                break

                        cvss_score = None
                        cvss_vector = None
                        metrics = cve_data.get("metrics", {})
                        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            if key in metrics and metrics[key]:
                                cd = metrics[key][0].get("cvssData", {})
                                cvss_score = cd.get("baseScore")
                                cvss_vector = cd.get("vectorString")
                                break

                        cwe_ids = []
                        for wp in cve_data.get("weaknesses", []):
                            for d in wp.get("description", []):
                                v = d.get("value", "")
                                if v.startswith("CWE-"):
                                    cwe_ids.append(v)

                        published = cve_data.get("published", "")[:10] or None
                        entries.append(CVEEntry(
                            id=cve_id, description=desc, cvss_score=cvss_score,
                            cvss_vector=cvss_vector, cwe_ids=cwe_ids or None,
                            exploit_available=False, published_at=published,
                        ))

                    if entries:
                        await kb.bulk_import(entries)
                        year_count += len(entries)

                    total_results = data.get("totalResults", 0)
                    start_idx += len(vulns)
                    if start_idx >= total_results:
                        break

                click.echo(f"  {y}: {year_count} CVEs imported")
                total += year_count

            final_count = await kb.count()
            click.echo(f"[OK] CVE database updated. Total: {final_count} CVEs ({total} new)")
        finally:
            await kb.close()

    click.echo("Updating CVE database from NVD API 2.0...")
    click.echo("(Rate-limited to ~50 requests/30s — large imports may take minutes)")
    asyncio.run(_run())


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
