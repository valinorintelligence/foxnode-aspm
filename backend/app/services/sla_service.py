import logging
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.product import Product

logger = logging.getLogger(__name__)

# Default SLA targets in hours per severity level
DEFAULT_SLA_TARGETS: dict[str, Optional[int]] = {
    "critical": 48,       # 48 hours (2 days)
    "high": 168,          # 7 days
    "medium": 720,        # 30 days
    "low": 2160,          # 90 days
    "info": None,         # No SLA for informational findings
}

# In-memory SLA configuration (persists for the lifetime of the process)
_sla_config: dict[str, Optional[int]] = dict(DEFAULT_SLA_TARGETS)


# --- Pydantic Models ---

class SLAStatus(BaseModel):
    finding_id: int
    title: str
    severity: str
    product_id: int
    product_name: Optional[str] = None
    sla_target_hours: Optional[int]
    elapsed_hours: float
    remaining_hours: Optional[float]
    is_breached: bool
    breach_percentage: float

    class Config:
        from_attributes = True


class ProductSLAMetrics(BaseModel):
    product_id: int
    product_name: str
    total_findings: int
    total_in_sla: int
    total_breached: int
    breach_rate: float
    avg_time_to_remediate_hours: Optional[float]
    by_severity: dict[str, dict]

    class Config:
        from_attributes = True


class RiskHeatmapCell(BaseModel):
    product_id: int
    product_name: str
    severity: str
    count: int
    breached_count: int
    risk_level: str  # low, medium, high, critical

    class Config:
        from_attributes = True


class SLAConfigResponse(BaseModel):
    targets: dict[str, Optional[int]]


class SLAConfigUpdate(BaseModel):
    critical: Optional[int] = None
    high: Optional[int] = None
    medium: Optional[int] = None
    low: Optional[int] = None
    info: Optional[int] = None


class SLASummary(BaseModel):
    total_findings: int
    in_sla: int
    breached: int
    breach_rate: float
    by_severity: dict[str, dict]


# --- Service Functions ---

def get_sla_config() -> dict[str, Optional[int]]:
    """Return the current SLA configuration."""
    return dict(_sla_config)


def update_sla_config(updates: SLAConfigUpdate) -> dict[str, Optional[int]]:
    """Update SLA targets. Only provided fields are changed."""
    update_data = updates.model_dump(exclude_unset=True)
    for severity, hours in update_data.items():
        if severity in _sla_config:
            _sla_config[severity] = hours
            logger.info("SLA target updated: %s = %s hours", severity, hours)
    return dict(_sla_config)


def _compute_sla_status(
    finding_id: int,
    title: str,
    severity: str,
    product_id: int,
    date_found: datetime,
    date_mitigated: Optional[datetime],
    product_name: Optional[str] = None,
) -> SLAStatus:
    """Compute SLA status for a single finding."""
    sla_target = _sla_config.get(severity)
    now = datetime.now(timezone.utc)

    # Use mitigated date if resolved, otherwise current time
    end_time = date_mitigated if date_mitigated else now
    elapsed = (end_time - date_found).total_seconds() / 3600.0

    if sla_target is None:
        # Info severity — no SLA enforcement
        return SLAStatus(
            finding_id=finding_id,
            title=title,
            severity=severity,
            product_id=product_id,
            product_name=product_name,
            sla_target_hours=None,
            elapsed_hours=round(elapsed, 2),
            remaining_hours=None,
            is_breached=False,
            breach_percentage=0.0,
        )

    remaining = sla_target - elapsed
    is_breached = elapsed > sla_target
    breach_percentage = min((elapsed / sla_target) * 100.0, 999.0) if sla_target > 0 else 0.0

    return SLAStatus(
        finding_id=finding_id,
        title=title,
        severity=severity,
        product_id=product_id,
        product_name=product_name,
        sla_target_hours=sla_target,
        elapsed_hours=round(elapsed, 2),
        remaining_hours=round(remaining, 2),
        is_breached=is_breached,
        breach_percentage=round(breach_percentage, 2),
    )


# Active statuses that count toward SLA tracking
_ACTIVE_STATUSES = {FindingStatus.ACTIVE, FindingStatus.VERIFIED}
_RESOLVED_STATUSES = {FindingStatus.MITIGATED, FindingStatus.FALSE_POSITIVE, FindingStatus.RISK_ACCEPTED}


async def get_all_sla_statuses(db: AsyncSession) -> list[SLAStatus]:
    """Compute SLA status for all active (non-duplicate) findings."""
    query = (
        select(Finding, Product.name)
        .join(Product, Finding.product_id == Product.id)
        .where(Finding.is_duplicate == False)  # noqa: E712
        .where(Finding.status.in_(_ACTIVE_STATUSES))
        .order_by(Finding.date_found.asc())
    )
    result = await db.execute(query)
    statuses = []
    for finding, product_name in result.all():
        severity_val = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        statuses.append(
            _compute_sla_status(
                finding_id=finding.id,
                title=finding.title,
                severity=severity_val,
                product_id=finding.product_id,
                date_found=finding.date_found,
                date_mitigated=finding.date_mitigated,
                product_name=product_name,
            )
        )
    return statuses


async def get_sla_summary(db: AsyncSession) -> SLASummary:
    """Aggregate SLA metrics across all products."""
    statuses = await get_all_sla_statuses(db)

    total = len(statuses)
    breached = sum(1 for s in statuses if s.is_breached)
    in_sla = total - breached

    by_severity: dict[str, dict] = {}
    for sev in FindingSeverity:
        sev_statuses = [s for s in statuses if s.severity == sev.value]
        sev_breached = sum(1 for s in sev_statuses if s.is_breached)
        sev_total = len(sev_statuses)
        by_severity[sev.value] = {
            "total": sev_total,
            "in_sla": sev_total - sev_breached,
            "breached": sev_breached,
            "breach_rate": round(sev_breached / sev_total * 100.0, 2) if sev_total > 0 else 0.0,
        }

    return SLASummary(
        total_findings=total,
        in_sla=in_sla,
        breached=breached,
        breach_rate=round(breached / total * 100.0, 2) if total > 0 else 0.0,
        by_severity=by_severity,
    )


async def get_product_sla_metrics(db: AsyncSession, product_id: int) -> ProductSLAMetrics:
    """Get SLA breakdown for a specific product."""
    # Verify product exists
    prod_result = await db.execute(select(Product).where(Product.id == product_id))
    product = prod_result.scalar_one_or_none()
    if product is None:
        raise ValueError(f"Product {product_id} not found")

    # Active findings
    active_query = (
        select(Finding)
        .where(
            Finding.product_id == product_id,
            Finding.is_duplicate == False,  # noqa: E712
            Finding.status.in_(_ACTIVE_STATUSES),
        )
    )
    active_result = await db.execute(active_query)
    active_findings = active_result.scalars().all()

    # Resolved findings for avg remediation time
    resolved_query = (
        select(Finding)
        .where(
            Finding.product_id == product_id,
            Finding.is_duplicate == False,  # noqa: E712
            Finding.status.in_(_RESOLVED_STATUSES),
            Finding.date_mitigated.isnot(None),
        )
    )
    resolved_result = await db.execute(resolved_query)
    resolved_findings = resolved_result.scalars().all()

    # Compute statuses for active findings
    statuses = []
    for f in active_findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        statuses.append(
            _compute_sla_status(
                finding_id=f.id,
                title=f.title,
                severity=sev,
                product_id=f.product_id,
                date_found=f.date_found,
                date_mitigated=f.date_mitigated,
                product_name=product.name,
            )
        )

    total = len(statuses)
    breached = sum(1 for s in statuses if s.is_breached)

    # Average remediation time from resolved findings
    avg_remediation = None
    if resolved_findings:
        durations = [
            (f.date_mitigated - f.date_found).total_seconds() / 3600.0
            for f in resolved_findings
        ]
        avg_remediation = round(sum(durations) / len(durations), 2)

    # By severity breakdown
    by_severity: dict[str, dict] = {}
    for sev in FindingSeverity:
        sev_statuses = [s for s in statuses if s.severity == sev.value]
        sev_breached = sum(1 for s in sev_statuses if s.is_breached)
        sev_total = len(sev_statuses)
        by_severity[sev.value] = {
            "total": sev_total,
            "in_sla": sev_total - sev_breached,
            "breached": sev_breached,
            "breach_rate": round(sev_breached / sev_total * 100.0, 2) if sev_total > 0 else 0.0,
        }

    return ProductSLAMetrics(
        product_id=product.id,
        product_name=product.name,
        total_findings=total,
        total_in_sla=total - breached,
        total_breached=breached,
        breach_rate=round(breached / total * 100.0, 2) if total > 0 else 0.0,
        avg_time_to_remediate_hours=avg_remediation,
        by_severity=by_severity,
    )


async def get_breached_findings(db: AsyncSession) -> list[SLAStatus]:
    """Return all SLA-breached findings, sorted by breach severity (highest percentage first)."""
    statuses = await get_all_sla_statuses(db)
    breached = [s for s in statuses if s.is_breached]
    breached.sort(key=lambda s: s.breach_percentage, reverse=True)
    return breached


def _determine_risk_level(count: int, breached_count: int, severity: str) -> str:
    """Determine risk level for a heatmap cell based on counts and severity."""
    if count == 0:
        return "low"

    breach_ratio = breached_count / count if count > 0 else 0.0
    severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    weight = severity_weight.get(severity, 0)

    # Risk score: combination of breach ratio and severity weight
    risk_score = (breach_ratio * 50) + (weight * 10) + min(count, 10)

    if risk_score >= 50 or (severity == "critical" and breached_count > 0):
        return "critical"
    elif risk_score >= 30 or (severity == "high" and breached_count > 0):
        return "high"
    elif risk_score >= 15:
        return "medium"
    return "low"


async def get_risk_heatmap(db: AsyncSession) -> list[RiskHeatmapCell]:
    """Generate risk heatmap data: products (rows) x severity levels (columns)."""
    # Get all products
    products_result = await db.execute(select(Product).order_by(Product.name))
    products = products_result.scalars().all()

    if not products:
        return []

    # Get all active SLA statuses
    all_statuses = await get_all_sla_statuses(db)

    # Build lookup: (product_id, severity) -> list of SLAStatus
    status_map: dict[tuple[int, str], list[SLAStatus]] = {}
    for s in all_statuses:
        key = (s.product_id, s.severity)
        status_map.setdefault(key, []).append(s)

    cells = []
    for product in products:
        for sev in FindingSeverity:
            key = (product.id, sev.value)
            sev_statuses = status_map.get(key, [])
            count = len(sev_statuses)
            breached_count = sum(1 for s in sev_statuses if s.is_breached)
            risk_level = _determine_risk_level(count, breached_count, sev.value)

            cells.append(
                RiskHeatmapCell(
                    product_id=product.id,
                    product_name=product.name,
                    severity=sev.value,
                    count=count,
                    breached_count=breached_count,
                    risk_level=risk_level,
                )
            )

    return cells
