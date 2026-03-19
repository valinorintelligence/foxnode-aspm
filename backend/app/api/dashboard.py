from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, extract

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.product import Product
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.schemas.schemas import DashboardStats, FindingResponse

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total_products = (await db.execute(select(func.count(Product.id)))).scalar() or 0
    total_findings = (await db.execute(select(func.count(Finding.id)))).scalar() or 0

    open_q = select(func.count(Finding.id)).where(Finding.status == FindingStatus.ACTIVE)
    open_findings = (await db.execute(open_q)).scalar() or 0

    severity_counts = {}
    for sev in FindingSeverity:
        count = (await db.execute(
            select(func.count(Finding.id)).where(
                Finding.severity == sev, Finding.status == FindingStatus.ACTIVE
            )
        )).scalar() or 0
        severity_counts[sev.value] = count

    by_status = {}
    status_result = await db.execute(
        select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
    )
    for row in status_result.all():
        by_status[row[0].value] = row[1]

    by_scanner = {}
    scanner_result = await db.execute(
        select(Finding.scanner, func.count(Finding.id))
        .where(Finding.scanner.isnot(None))
        .group_by(Finding.scanner)
        .order_by(func.count(Finding.id).desc())
        .limit(10)
    )
    for row in scanner_result.all():
        by_scanner[row[0]] = row[1]

    recent_result = await db.execute(
        select(Finding).order_by(Finding.created_at.desc()).limit(10)
    )
    recent_findings = [FindingResponse.model_validate(f) for f in recent_result.scalars().all()]

    # Top vulnerable products
    top_products_result = await db.execute(
        select(Product.name, func.count(Finding.id).label("count"))
        .join(Finding, Finding.product_id == Product.id)
        .where(Finding.status == FindingStatus.ACTIVE)
        .group_by(Product.name)
        .order_by(func.count(Finding.id).desc())
        .limit(5)
    )
    top_vulnerable = [{"name": row[0], "count": row[1]} for row in top_products_result.all()]

    return DashboardStats(
        total_products=total_products,
        total_findings=total_findings,
        open_findings=open_findings,
        critical_findings=severity_counts.get("critical", 0),
        high_findings=severity_counts.get("high", 0),
        medium_findings=severity_counts.get("medium", 0),
        low_findings=severity_counts.get("low", 0),
        findings_by_severity=severity_counts,
        findings_by_status=by_status,
        findings_by_scanner=by_scanner,
        recent_findings=recent_findings,
        risk_trend=[],
        top_vulnerable_products=top_vulnerable,
    )
