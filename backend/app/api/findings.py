from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.schemas.schemas import FindingCreate, FindingResponse, FindingUpdate

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    severity: FindingSeverity = Query(None),
    status: FindingStatus = Query(None),
    product_id: int = Query(None),
    scanner: str = Query(None),
    search: str = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Finding).offset(skip).limit(limit).order_by(Finding.created_at.desc())
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if product_id:
        query = query.where(Finding.product_id == product_id)
    if scanner:
        query = query.where(Finding.scanner == scanner)
    if search:
        query = query.where(Finding.title.ilike(f"%{search}%"))
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=FindingResponse, status_code=201)
async def create_finding(
    request: FindingCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = Finding(**request.model_dump(), reporter_id=current_user.id)
    finding.compute_hash()
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return finding


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: int,
    request: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    update_data = request.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(finding, key, value)
    await db.flush()
    await db.refresh(finding)
    return finding


@router.get("/stats/summary")
async def findings_summary(
    product_id: int = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    base = select(func.count(Finding.id)).where(Finding.is_duplicate == False)
    if product_id:
        base = base.where(Finding.product_id == product_id)

    severity_q = (
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.is_duplicate == False)
        .group_by(Finding.severity)
    )
    status_q = (
        select(Finding.status, func.count(Finding.id))
        .where(Finding.is_duplicate == False)
        .group_by(Finding.status)
    )
    if product_id:
        severity_q = severity_q.where(Finding.product_id == product_id)
        status_q = status_q.where(Finding.product_id == product_id)

    total = (await db.execute(base)).scalar() or 0
    by_severity = {row[0].value: row[1] for row in (await db.execute(severity_q)).all()}
    by_status = {row[0].value: row[1] for row in (await db.execute(status_q)).all()}

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
    }
