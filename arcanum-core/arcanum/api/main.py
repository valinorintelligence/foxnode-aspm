"""FastAPI application for Arcanum Core Web UI."""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from ..core.config import get_config
from ..core.database import Database
from ..core.cve_kb import CVEKnowledgeBase
from ..core.stash import StashManager
from ..core.alerts import AlertEngine
from ..core.reports import ReportEngine
from ..core.demo_data import seed_all_demo_data
from ..agent.llm import OllamaClient
from ..agent.session import SessionManager

from .routes import sessions, tools, findings, stash, cve, reports
from .websocket import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources."""
    config = get_config()

    # Initialize database
    db = Database(config.data_dir / "arcanum.db")
    await db.connect()
    await db.init_db()
    app.state.db = db

    # Initialize CVE KB
    cve_kb = CVEKnowledgeBase(config.cve_db)
    await cve_kb.connect()
    app.state.cve_kb = cve_kb

    # Initialize managers
    app.state.session_mgr = SessionManager(db)
    app.state.stash_mgr = StashManager(db)
    app.state.alert_engine = AlertEngine()
    app.state.report_engine = ReportEngine()

    # Initialize LLM client
    app.state.llm = OllamaClient(
        base_url=config.ollama_url,
        model=config.ollama_model,
        timeout=config.ollama_timeout,
        num_ctx=config.ollama_num_ctx,
        temperature=config.ollama_temperature,
        num_predict=config.ollama_num_predict,
        repeat_penalty=config.ollama_repeat_penalty,
        enable_thinking=config.ollama_enable_thinking,
    )

    # Active sessions/engines
    app.state.active_engines = {}

    # Seed demo data on first run
    try:
        result = await seed_all_demo_data(db, cve_kb)
        if any(v > 0 for v in result.values()):
            import logging
            logging.getLogger("arcanum").info(f"Demo data seeded: {result}")
    except Exception:
        pass  # Non-fatal — demo data is optional

    yield

    # Cleanup
    await db.close()
    await cve_kb.close()
    await app.state.llm.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Arcanum Core",
        description="Autonomous AI-Powered Security Reconnaissance Platform",
        version="3.0.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API routes
    app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
    app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
    app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
    app.include_router(stash.router, prefix="/api/stash", tags=["stash"])
    app.include_router(cve.router, prefix="/api/cve", tags=["cve"])
    app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
    app.include_router(ws_router)

    # Health check
    @app.get("/api/health")
    async def health():
        try:
            llm_ok = await app.state.llm.check_health()
        except Exception:
            llm_ok = False
        return {
            "status": "ok",
            "version": "3.0.0",
            "llm_connected": llm_ok,
        }

    # Dashboard stats
    @app.get("/api/stats")
    async def stats():
        sessions = await app.state.db.fetch_all("SELECT status FROM sessions")
        findings = await app.state.db.fetch_all("SELECT severity FROM findings")
        stash_count = await app.state.db.fetch_one("SELECT COUNT(*) as cnt FROM stash")
        cve_count = await app.state.cve_kb.count()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "sessions": {
                "total": len(sessions),
                "running": sum(1 for s in sessions if s["status"] == "running"),
                "complete": sum(1 for s in sessions if s["status"] == "complete"),
            },
            "findings": {
                "total": len(findings),
                **severity_counts,
            },
            "stash": stash_count["cnt"] if stash_count else 0,
            "cves": cve_count,
        }

    # Demo seed endpoint
    @app.post("/api/demo/seed")
    async def demo_seed():
        from ..core.demo_data import seed_all_demo_data
        result = await seed_all_demo_data(app.state.db, app.state.cve_kb)
        return {"seeded": result}

    # Serve frontend — check multiple locations (dev vs Docker)
    frontend_candidates = [
        Path(__file__).parent.parent.parent / "frontend",  # dev: repo root
        Path("/app/frontend"),                              # Docker workdir
    ]
    frontend_dir = next((d for d in frontend_candidates if (d / "index.html").exists()), None)
    if frontend_dir:
        assets_dir = frontend_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

        @app.get("/")
        async def serve_frontend():
            return FileResponse(frontend_dir / "index.html")

    return app


app = create_app()
