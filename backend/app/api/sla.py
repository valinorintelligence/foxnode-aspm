from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User, UserRole
from app.services.sla_service import (
    get_sla_config,
    update_sla_config,
    get_sla_summary,
    get_product_sla_metrics,
    get_breached_findings,
    get_risk_heatmap,
    SLAConfigUpdate,
    SLAConfigResponse,
    SLASummary,
    SLAStatus,
    ProductSLAMetrics,
    RiskHeatmapCell,
)

router = APIRouter(prefix="/sla", tags=["SLA Tracker"])


@router.get("/status", response_model=SLASummary)
async def sla_status_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get SLA status across all products: in_sla count, breached count, breach rate."""
    return await get_sla_summary(db)


@router.get("/product/{product_id}", response_model=ProductSLAMetrics)
async def sla_product_breakdown(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """SLA breakdown for a specific product."""
    try:
        return await get_product_sla_metrics(db, product_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/breaches", response_model=list[SLAStatus])
async def sla_breaches(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all SLA-breached findings sorted by breach severity (highest percentage first)."""
    return await get_breached_findings(db)


@router.get("/heatmap", response_model=list[RiskHeatmapCell])
async def risk_heatmap(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Risk heatmap data: products (rows) x severity levels (columns) matrix."""
    return await get_risk_heatmap(db)


@router.get("/config", response_model=SLAConfigResponse)
async def get_sla_configuration(
    current_user: User = Depends(get_current_user),
):
    """Get current SLA configuration (target hours per severity)."""
    return SLAConfigResponse(targets=get_sla_config())


@router.post("/config", response_model=SLAConfigResponse)
async def update_sla_configuration(
    config: SLAConfigUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update SLA targets. Admin only."""
    if current_user.role != UserRole.ADMIN and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Only admins can update SLA configuration")
    updated = update_sla_config(config)
    return SLAConfigResponse(targets=updated)
