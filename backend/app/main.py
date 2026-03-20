from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import engine, Base
from app.api import auth, products, findings, engagements, dashboard, integrations, scans, users, jira, notifications, scorecard, triage, sla, compliance, attack_path, api_security, metrics, security_agent, sbom, copilot, llm_scanner


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Open-source Application Security Posture Management platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(products.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(engagements.router, prefix="/api/v1")
app.include_router(integrations.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(jira.router, prefix="/api/v1")
app.include_router(notifications.router, prefix="/api/v1")
app.include_router(scorecard.router, prefix="/api/v1")
app.include_router(triage.router, prefix="/api/v1")
app.include_router(sla.router, prefix="/api/v1")
app.include_router(compliance.router, prefix="/api/v1")
app.include_router(attack_path.router, prefix="/api/v1")
app.include_router(api_security.router, prefix="/api/v1")
app.include_router(metrics.router, prefix="/api/v1")
app.include_router(security_agent.router, prefix="/api/v1")
app.include_router(sbom.router, prefix="/api/v1")
app.include_router(copilot.router, prefix="/api/v1")
app.include_router(llm_scanner.router, prefix="/api/v1")


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "version": settings.APP_VERSION}
