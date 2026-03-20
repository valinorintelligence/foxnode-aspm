"""LLM Vulnerability Scanner API — AI/ML-specific security analysis endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.product import Product
from app.services.llm_scanner_service import LLMScannerService

router = APIRouter(prefix="/llm-scanner", tags=["LLM Vulnerability Scanner"])

_service = LLMScannerService()


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ScanCodeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=100_000, description="Source code to scan")
    language: str = Field(default="python", description="Programming language")
    context: Optional[str] = Field(default=None, max_length=1000, description="Optional context about the codebase")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_product_or_404(product_id: int, db: AsyncSession) -> Product:
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan")
async def scan_code_snippet(
    body: ScanCodeRequest,
    current_user: User = Depends(get_current_user),
):
    """Scan a code snippet for AI/ML-specific vulnerabilities.

    Uses pattern matching and heuristic analysis to identify risks
    such as prompt injection, insecure model loading, API key exposure,
    and more. No external API calls are made.
    """
    results = _service.scan_code_snippet(
        code=body.code,
        language=body.language,
        context=body.context,
    )

    severity_counts = {}
    for r in results:
        sev = r["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "total_vulnerabilities": len(results),
        "severity_counts": severity_counts,
        "language": body.language,
        "vulnerabilities": results,
    }


@router.get("/product/{product_id}")
async def get_product_ai_risk(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get AI security risk assessment for a product.

    Analyzes existing findings to determine AI exposure level,
    prompt injection risk, data poisoning risk, and model supply
    chain risk. Returns actionable recommendations.
    """
    product = await _get_product_or_404(product_id, db)
    assessment = await _service.get_ai_risk_assessment(db, product_id)
    assessment["product_name"] = product.name
    return assessment


@router.get("/owasp-llm/{product_id}")
async def get_owasp_llm_mapping(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Map product findings to the OWASP LLM Top 10 categories.

    Returns each LLM01-LLM10 category with associated findings,
    risk levels, and counts.
    """
    product = await _get_product_or_404(product_id, db)
    mapping = await _service.get_owasp_llm_top10_mapping(db, product_id)
    mapping["product_name"] = product.name
    return mapping


@router.post("/analyze-findings/{product_id}")
async def analyze_findings_for_ai_risks(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Re-analyze existing findings to identify AI/ML-related security issues.

    Scans finding titles, descriptions, and file paths for AI-related
    keywords that traditional scanners may have miscategorized.
    """
    product = await _get_product_or_404(product_id, db)
    ai_findings = await _service.scan_product_findings(db, product_id)

    return {
        "product_id": product_id,
        "product_name": product.name,
        "total_ai_findings": len(ai_findings),
        "findings": ai_findings,
    }


@router.get("/overview")
async def get_org_ai_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get organisation-wide AI security overview.

    Aggregates AI risk assessments across all products, showing
    overall AI risk level, exposure distribution, and top
    recommendations.
    """
    return await _service.get_org_overview(db)
