from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.product import Engagement
from app.schemas.schemas import EngagementCreate, EngagementResponse

router = APIRouter(prefix="/engagements", tags=["Engagements"])


@router.get("", response_model=list[EngagementResponse])
async def list_engagements(
    product_id: int = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Engagement).offset(skip).limit(limit).order_by(Engagement.created_at.desc())
    if product_id:
        query = query.where(Engagement.product_id == product_id)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=EngagementResponse, status_code=201)
async def create_engagement(
    request: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    engagement = Engagement(**request.model_dump(), lead_id=current_user.id)
    db.add(engagement)
    await db.flush()
    await db.refresh(engagement)
    return engagement
