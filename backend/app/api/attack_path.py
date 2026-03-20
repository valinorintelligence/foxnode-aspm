from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.product import Product
from app.services.attack_path_service import AttackPathService

router = APIRouter(prefix="/attack-paths", tags=["Attack Paths"])

_service = AttackPathService()


@router.get("/product/{product_id}")
async def discover_attack_paths(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Discover attack paths for a product by matching CWE combinations."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    paths = await _service.discover_attack_paths(db, product_id)
    return {
        "product_id": product_id,
        "product_name": product.name,
        "attack_paths": paths,
        "total": len(paths),
    }


@router.get("/surface/{product_id}")
async def get_attack_surface(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the attack surface mapping for a product."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    surface = await _service.get_attack_surface(db, product_id)
    surface["product_name"] = product.name
    return surface


@router.get("/graph/{product_id}")
async def get_risk_graph(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get graph data (nodes + edges) for attack path visualization."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    graph = await _service.calculate_risk_graph(db, product_id)
    graph["product_name"] = product.name
    return graph


@router.get("/overview")
async def get_attack_path_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get org-wide attack path summary across all products."""
    return await _service.get_overview(db)
