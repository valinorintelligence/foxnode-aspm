"""Security Metrics & KPI Dashboard API endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.services.metrics_service import (
    calculate_mttr,
    calculate_finding_aging,
    calculate_risk_burndown,
    calculate_team_velocity,
    calculate_scanner_effectiveness,
    calculate_vulnerability_trends,
    get_executive_summary,
    get_kpi_dashboard,
)

router = APIRouter(prefix="/metrics", tags=["Metrics & KPIs"])


@router.get("/kpi")
async def kpi_dashboard(
    product_id: Optional[int] = Query(None, description="Filter by product"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Full KPI dashboard with all metrics combined."""
    return await get_kpi_dashboard(db, product_id=product_id)


@router.get("/mttr")
async def mttr_metrics(
    product_id: Optional[int] = Query(None, description="Filter by product"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mean Time To Remediate breakdown by severity with 30-day trend."""
    return await calculate_mttr(db, product_id=product_id, severity=severity)


@router.get("/aging")
async def finding_aging(
    product_id: Optional[int] = Query(None, description="Filter by product"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Finding aging analysis grouped by age buckets and severity."""
    return await calculate_finding_aging(db, product_id=product_id)


@router.get("/burndown")
async def risk_burndown(
    product_id: Optional[int] = Query(None, description="Filter by product"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Risk burndown chart data for the last 30 days."""
    return await calculate_risk_burndown(db, product_id=product_id)


@router.get("/velocity")
async def team_velocity(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Team velocity metrics: findings resolved per user and weekly trends."""
    return await calculate_team_velocity(db)


@router.get("/scanner-effectiveness")
async def scanner_effectiveness(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scanner ROI analysis: findings per scanner, duplicate rate, severity distribution."""
    return await calculate_scanner_effectiveness(db)


@router.get("/trends")
async def vulnerability_trends(
    days: int = Query(90, ge=7, le=365, description="Number of days to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Vulnerability trends: new vs resolved findings over time."""
    return await calculate_vulnerability_trends(db, days=days)


@router.get("/executive-summary")
async def executive_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Executive-ready security summary with risk level, trends, and action items."""
    return await get_executive_summary(db)
