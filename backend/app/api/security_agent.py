from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.product import Product
from app.services import security_agent_service

router = APIRouter(prefix="/agent", tags=["Security Agent"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str
    product_id: Optional[int] = None


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

@router.post("/analyze/{product_id}")
async def analyze_product(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run a full AI security posture analysis for a product."""
    await _get_product_or_404(product_id, db)
    result = await security_agent_service.analyze_product_posture(db, product_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/chat")
async def chat(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Chat-style endpoint for natural language security questions."""
    if body.product_id:
        await _get_product_or_404(body.product_id, db)
    result = await security_agent_service.answer_security_question(
        db, body.message, product_id=body.product_id,
    )
    return result


@router.get("/report/{product_id}")
async def executive_report(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate an executive security report for a product."""
    await _get_product_or_404(product_id, db)
    result = await security_agent_service.generate_executive_report(db, product_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/attack-chains/{product_id}")
async def attack_chains(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Identify potential attack chains from product findings."""
    await _get_product_or_404(product_id, db)
    chains = await security_agent_service.identify_attack_chains(db, product_id)
    return {"product_id": product_id, "attack_chains": chains, "count": len(chains)}
