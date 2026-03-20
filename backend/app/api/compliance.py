from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.services.compliance_service import ComplianceService

router = APIRouter(prefix="/compliance", tags=["Compliance"])

_service = ComplianceService()


@router.get("/frameworks")
async def list_frameworks(
    current_user: User = Depends(get_current_user),
):
    """List all supported compliance frameworks."""
    return _service.list_frameworks()


@router.get("/overview")
async def compliance_overview(
    product_id: int = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Summary of compliance posture across all frameworks."""
    return await _service.generate_overview(db, product_id)


@router.get("/report/{framework_id}")
async def compliance_report(
    framework_id: str,
    product_id: int = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a full compliance report for a specific framework."""
    try:
        report = await _service.generate_report(db, framework_id, product_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' not found")

    return {
        "framework_id": report.framework_id,
        "framework_name": report.framework_name,
        "version": report.version,
        "total_controls": report.total_controls,
        "controls_with_findings": report.controls_with_findings,
        "passing_controls": report.passing_controls,
        "failing_controls": report.failing_controls,
        "compliance_percentage": report.compliance_percentage,
        "mapped_findings_count": report.mapped_findings_count,
        "gaps": [
            {
                "control_id": g.control_id,
                "title": g.title,
                "gap_type": g.gap_type,
                "details": g.details,
            }
            for g in report.gaps
        ],
    }


@router.get("/gaps/{framework_id}")
async def compliance_gaps(
    framework_id: str,
    product_id: int = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Detailed gap analysis for a specific framework."""
    try:
        return await _service.generate_gap_analysis(db, framework_id, product_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' not found")
