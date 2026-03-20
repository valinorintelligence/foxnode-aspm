from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.finding import Finding, FindingStatus
from app.models.product import Product
from app.services.triage_service import TriageService

router = APIRouter(prefix="/triage", tags=["Triage"])

_triage_service = TriageService()


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

@router.post("/analyze/{finding_id}")
async def analyze_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Triage a single finding and return the TriageResult."""
    finding = await _get_finding_or_404(finding_id, db)
    product = await _get_product_or_404(finding.product_id, db)
    criticality = product.business_criticality or "medium"

    result = _triage_service.triage_finding(finding, product_criticality=criticality)
    return result.to_dict()


@router.post("/bulk-analyze")
async def bulk_analyze(
    product_id: int = Query(..., description="Product whose findings should be triaged"),
    severity: str = Query(None, description="Optional severity filter"),
    status: str = Query(None, description="Optional status filter"),
    limit: int = Query(500, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Triage all findings for a product and return sorted results."""
    product = await _get_product_or_404(product_id, db)

    query = (
        select(Finding)
        .where(Finding.product_id == product_id)
        .order_by(Finding.created_at.desc())
        .limit(limit)
    )
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)

    result = await db.execute(query)
    findings = list(result.scalars().all())

    if not findings:
        return {"results": [], "total": 0}

    criticality = product.business_criticality or "medium"
    triage_results = _triage_service.triage_findings(findings, product_criticality=criticality)

    return {
        "results": [r.to_dict() for r in triage_results],
        "total": len(triage_results),
    }


@router.get("/summary/{product_id}")
async def triage_summary(
    product_id: int,
    limit: int = Query(500, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a triage summary for a product: priority counts, FP candidates, groupings."""
    product = await _get_product_or_404(product_id, db)

    query = (
        select(Finding)
        .where(Finding.product_id == product_id)
        .where(Finding.status.notin_([FindingStatus.FALSE_POSITIVE, FindingStatus.OUT_OF_SCOPE]))
        .order_by(Finding.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(query)
    findings = list(result.scalars().all())

    if not findings:
        return {
            "product_id": product_id,
            "total_findings": 0,
            "counts_by_priority": {},
            "top_false_positive_candidates": [],
            "grouped_findings": {},
        }

    criticality = product.business_criticality or "medium"
    triage_results = _triage_service.triage_findings(findings, product_criticality=criticality)
    summary = _triage_service.build_summary(product_id, triage_results)

    return summary.to_dict()
