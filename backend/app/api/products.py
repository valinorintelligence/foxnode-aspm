from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.product import Product
from app.models.finding import Finding, FindingSeverity
from app.schemas.schemas import ProductCreate, ProductResponse

router = APIRouter(prefix="/products", tags=["Products"])


@router.get("", response_model=list[ProductResponse])
async def list_products(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: str = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Product).offset(skip).limit(limit).order_by(Product.created_at.desc())
    if search:
        query = query.where(Product.name.ilike(f"%{search}%"))
    result = await db.execute(query)
    products = result.scalars().all()

    response = []
    for p in products:
        counts_result = await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.product_id == p.id, Finding.status == "active")
            .group_by(Finding.severity)
        )
        counts = {row[0].value: row[1] for row in counts_result.all()}
        prod_resp = ProductResponse.model_validate(p)
        prod_resp.finding_counts = counts
        response.append(prod_resp)
    return response


@router.post("", response_model=ProductResponse, status_code=201)
async def create_product(
    request: ProductCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    product = Product(**request.model_dump(), owner_id=current_user.id)
    db.add(product)
    await db.flush()
    await db.refresh(product)
    return product


@router.get("/{product_id}", response_model=ProductResponse)
async def get_product(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


@router.delete("/{product_id}", status_code=204)
async def delete_product(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    await db.delete(product)
