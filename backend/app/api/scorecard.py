from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.product import Product
from app.services.scorecard_service import ScorecardService

router = APIRouter(prefix="/scorecard", tags=["Scorecard"])

_service = ScorecardService()


@router.get("/product/{product_id}")
async def get_product_scorecard(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the security scorecard for a single product."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    card = await _service.calculate_product_score(db, product_id)
    card["product_name"] = product.name
    return card


@router.get("/overview")
async def get_scorecard_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get org-wide score, all product scores, and the team leaderboard."""
    return await _service.calculate_org_overview(db)


@router.get("/trends")
async def get_scorecard_trends(
    product_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get score trend data (last 30 days) for charts.

    Pass *product_id* to get trends for a specific product.
    Omit it to get the org-wide trend.
    """
    if product_id is not None:
        result = await db.execute(select(Product).where(Product.id == product_id))
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Product not found")

    return await _service.get_trend_data(db, product_id=product_id)
