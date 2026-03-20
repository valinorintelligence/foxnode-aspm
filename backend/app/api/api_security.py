from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.product import Product
from app.models.finding import Endpoint
from app.services.api_security_service import ApiSecurityService

router = APIRouter(prefix="/api-security", tags=["API Security"])

_service = ApiSecurityService()


class OpenApiSpecImport(BaseModel):
    """Request body for importing an OpenAPI/Swagger spec."""
    spec: dict


@router.get("/posture/{product_id}")
async def get_api_posture(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Analyse API security posture for a product."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    posture = await _service.analyze_api_posture(db, product_id)
    posture["product_name"] = product.name
    return posture


@router.post("/import-spec/{product_id}")
async def import_openapi_spec(
    product_id: int,
    body: OpenApiSpecImport,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Import an OpenAPI/Swagger spec and store discovered endpoints.

    Parses the spec, creates Endpoint records for the product, and
    correlates existing findings with the discovered API endpoints.
    """
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Parse the spec
    parsed_endpoints = _service.parse_openapi_spec(body.spec)
    if not parsed_endpoints:
        raise HTTPException(status_code=400, detail="No endpoints found in spec")

    # Determine host from spec
    host = ""
    servers = body.spec.get("servers", [])
    if servers and isinstance(servers, list):
        host = servers[0].get("url", "")
    elif body.spec.get("host"):
        host = body.spec["host"]

    # Create Endpoint records
    created = 0
    for ep in parsed_endpoints:
        endpoint = Endpoint(
            protocol="https",
            host=host,
            path=ep["path"],
            product_id=product_id,
            finding_id=0,  # No associated finding yet
        )
        # Check if endpoint already exists to avoid duplicates
        existing = await db.execute(
            select(Endpoint).where(
                Endpoint.product_id == product_id,
                Endpoint.path == ep["path"],
                Endpoint.host == host,
            )
        )
        if not existing.scalar_one_or_none():
            db.add(endpoint)
            created += 1

    # Correlate findings with new endpoints
    correlated = await _service.correlate_api_findings(db, product_id, parsed_endpoints)

    return {
        "product_id": product_id,
        "product_name": product.name,
        "endpoints_parsed": len(parsed_endpoints),
        "endpoints_created": created,
        "endpoints": correlated,
    }


@router.get("/endpoints/{product_id}")
async def list_api_endpoints(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all tracked API endpoints for a product."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    ep_result = await db.execute(
        select(Endpoint).where(Endpoint.product_id == product_id)
    )
    endpoints = ep_result.scalars().all()

    return {
        "product_id": product_id,
        "product_name": product.name,
        "total": len(endpoints),
        "endpoints": [
            {
                "id": ep.id,
                "protocol": ep.protocol,
                "host": ep.host,
                "port": ep.port,
                "path": ep.path,
                "query": ep.query,
            }
            for ep in endpoints
        ],
    }


@router.get("/risks/{product_id}")
async def get_api_risks(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get API-specific risk score and breakdown for a product."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    risk = await _service.get_api_risk_score(db, product_id)
    risk["product_name"] = product.name
    return risk


@router.get("/overview")
async def get_api_security_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get org-wide API security overview across all products."""
    return await _service.get_api_overview(db)
