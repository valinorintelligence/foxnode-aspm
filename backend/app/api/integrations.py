from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.integration import Integration
from app.schemas.schemas import IntegrationCreate, IntegrationResponse

router = APIRouter(prefix="/integrations", tags=["Integrations"])

SUPPORTED_TOOLS = [
    {"name": "Trivy", "type": "container", "description": "Container and filesystem vulnerability scanner"},
    {"name": "Semgrep", "type": "sast", "description": "Lightweight static analysis for many languages"},
    {"name": "SonarQube", "type": "sast", "description": "Continuous code quality and security inspection"},
    {"name": "Snyk", "type": "sca", "description": "Developer-first security for dependencies"},
    {"name": "OWASP ZAP", "type": "dast", "description": "Dynamic application security testing"},
    {"name": "Nuclei", "type": "dast", "description": "Fast and customizable vulnerability scanner"},
    {"name": "Burp Suite", "type": "dast", "description": "Web security testing toolkit"},
    {"name": "Checkov", "type": "iac", "description": "Infrastructure as code static analysis"},
    {"name": "tfsec", "type": "iac", "description": "Terraform security scanner"},
    {"name": "Gitleaks", "type": "secret_detection", "description": "Secret detection in git repos"},
    {"name": "TruffleHog", "type": "secret_detection", "description": "Find leaked credentials"},
    {"name": "AWS Security Hub", "type": "cloud", "description": "AWS cloud security posture"},
    {"name": "Prowler", "type": "cloud", "description": "AWS/Azure/GCP security assessments"},
    {"name": "ScoutSuite", "type": "cloud", "description": "Multi-cloud security auditing"},
    {"name": "Nmap", "type": "infrastructure", "description": "Network discovery and security auditing"},
    {"name": "OpenVAS", "type": "infrastructure", "description": "Open vulnerability assessment scanner"},
    {"name": "Qualys", "type": "infrastructure", "description": "Enterprise vulnerability management"},
    {"name": "Dependency-Check", "type": "sca", "description": "OWASP dependency vulnerability detection"},
    {"name": "Bandit", "type": "sast", "description": "Python code security analysis"},
    {"name": "ESLint Security", "type": "sast", "description": "JavaScript security linting rules"},
    {"name": "Jira", "type": "issue_tracker", "description": "Issue and project tracking"},
    {"name": "GitHub Issues", "type": "issue_tracker", "description": "GitHub issue tracking"},
    {"name": "Slack", "type": "notification", "description": "Team messaging and alerts"},
    {"name": "PagerDuty", "type": "notification", "description": "Incident management"},
]


@router.get("/supported-tools")
async def get_supported_tools():
    return SUPPORTED_TOOLS


@router.get("", response_model=list[IntegrationResponse])
async def list_integrations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Integration).order_by(Integration.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=IntegrationResponse, status_code=201)
async def create_integration(
    request: IntegrationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    integration = Integration(**request.model_dump(), created_by_id=current_user.id)
    db.add(integration)
    await db.flush()
    await db.refresh(integration)
    return integration


@router.delete("/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    await db.delete(integration)
