"""
AI Remediation Copilot API Router
===================================
Provides endpoints for LLM-quality remediation advice powered by a
rule-based template engine.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.product import Product
from app.services.ai_copilot_service import AICopilotService

router = APIRouter(prefix="/copilot", tags=["AI Copilot"])

_copilot_service = AICopilotService()


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class BulkRemediateRequest(BaseModel):
    product_id: int
    severity_filter: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_finding_or_404(finding_id: int, db: AsyncSession) -> Finding:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


async def _get_product_or_404(product_id: int, db: AsyncSession) -> Product:
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/remediate/{finding_id}")
async def remediate_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate AI-powered remediation advice for a single finding."""
    finding = await _get_finding_or_404(finding_id, db)
    result = _copilot_service.generate_remediation(finding)
    return result.to_dict()


@router.post("/bulk-remediate")
async def bulk_remediate(
    request: BulkRemediateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate remediation advice for all findings of a product.

    Optionally filter by severity (critical, high, medium, low, info).
    """
    product = await _get_product_or_404(request.product_id, db)

    query = (
        select(Finding)
        .where(Finding.product_id == request.product_id)
        .where(Finding.status.notin_([FindingStatus.FALSE_POSITIVE, FindingStatus.OUT_OF_SCOPE]))
        .order_by(Finding.created_at.desc())
        .limit(500)
    )
    if request.severity_filter:
        try:
            severity_enum = FindingSeverity(request.severity_filter.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity filter: {request.severity_filter}. "
                       f"Valid values: critical, high, medium, low, info.",
            )
        query = query.where(Finding.severity == severity_enum)

    result = await db.execute(query)
    findings = list(result.scalars().all())

    if not findings:
        return {"results": [], "total": 0, "product_id": request.product_id}

    remediations = _copilot_service.generate_bulk_remediation(findings)

    # Build summary statistics
    cwe_coverage = sum(1 for r in remediations if r.confidence == "high")
    total_effort = sum(r.estimated_effort["estimated_hours"] for r in remediations)

    return {
        "results": [r.to_dict() for r in remediations],
        "total": len(remediations),
        "product_id": request.product_id,
        "summary": {
            "findings_with_specific_guidance": cwe_coverage,
            "findings_with_general_guidance": len(remediations) - cwe_coverage,
            "total_estimated_hours": round(total_effort, 1),
        },
    }


@router.get("/developer-summary/{finding_id}")
async def developer_summary(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a short, developer-friendly remediation summary for a finding."""
    finding = await _get_finding_or_404(finding_id, db)
    summary = _copilot_service.get_developer_summary(finding)
    return summary.to_dict()


@router.get("/stats")
async def copilot_stats(
    current_user: User = Depends(get_current_user),
):
    """Return statistics about AI Copilot remediation template coverage."""
    return _copilot_service.get_coverage_stats()
