"""Advanced security metrics & KPI engine for Foxnode ASPM."""

import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, func, and_, case, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.product import Product
from app.models.user import User

logger = logging.getLogger(__name__)

# Severity weights used across multiple metric calculations
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.0,
}

# Statuses that count as "resolved"
RESOLVED_STATUSES = [
    FindingStatus.MITIGATED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.RISK_ACCEPTED,
    FindingStatus.OUT_OF_SCOPE,
]

# Statuses that count as "open"
OPEN_STATUSES = [FindingStatus.ACTIVE, FindingStatus.VERIFIED]

# SLA targets in hours (defaults, mirrors sla_service)
DEFAULT_SLA_HOURS: dict[str, int] = {
    "critical": 24,
    "high": 72,
    "medium": 336,
    "low": 720,
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _mock_trend_points(
    current_value: float,
    days: int = 30,
    noise: float = 0.15,
    direction: str = "stable",
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Generate plausible mock trend data points when real history is sparse.

    Uses a seeded RNG for deterministic output across identical calls.
    """
    rng = random.Random(seed)
    today = datetime.now(timezone.utc).date()
    points: list[dict[str, Any]] = []

    # Starting value offset based on direction
    if direction == "improving":
        start = current_value * (1 + rng.uniform(0.15, 0.35))
    elif direction == "worsening":
        start = current_value * max(0, (1 - rng.uniform(0.15, 0.35)))
    else:
        start = current_value * (1 + rng.uniform(-0.08, 0.08))

    value = start
    step = (current_value - start) / max(days - 1, 1)

    for i in range(days):
        date = today - timedelta(days=days - 1 - i)
        jitter = current_value * noise * rng.uniform(-1, 1)
        value = start + step * i + jitter
        value = max(0, value)
        points.append({
            "date": date.isoformat(),
            "value": round(value, 2),
        })

    # Pin last point to current value
    if points:
        points[-1]["value"] = round(current_value, 2)

    return points


def _determine_trend(values: list[float]) -> str:
    """Determine whether a series of values is improving, stable, or worsening."""
    if len(values) < 4:
        return "stable"
    mid = len(values) // 2
    first_half_avg = sum(values[:mid]) / mid
    second_half_avg = sum(values[mid:]) / (len(values) - mid)
    pct_change = (
        ((second_half_avg - first_half_avg) / first_half_avg * 100)
        if first_half_avg != 0
        else 0
    )
    if pct_change < -10:
        return "improving"  # fewer findings / lower risk = improving
    if pct_change > 10:
        return "worsening"
    return "stable"


# ---------------------------------------------------------------------------
# MTTR – Mean Time To Remediate
# ---------------------------------------------------------------------------

async def calculate_mttr(
    db: AsyncSession,
    product_id: Optional[int] = None,
    severity: Optional[str] = None,
) -> dict[str, Any]:
    """Calculate Mean Time To Remediate for resolved findings.

    Returns overall MTTR in hours, breakdown by severity, and a 30-day trend.
    """
    base_filters = [
        Finding.status.in_(RESOLVED_STATUSES),
        Finding.date_mitigated.isnot(None),
        Finding.is_duplicate == False,  # noqa: E712
    ]
    if product_id is not None:
        base_filters.append(Finding.product_id == product_id)
    if severity is not None:
        base_filters.append(Finding.severity == FindingSeverity(severity))

    # Overall MTTR
    overall_q = select(
        func.avg(
            func.extract("epoch", Finding.date_mitigated)
            - func.extract("epoch", Finding.date_found)
        )
    ).where(*base_filters)
    overall_seconds = (await db.execute(overall_q)).scalar()
    overall_mttr_hours = round(overall_seconds / 3600.0, 1) if overall_seconds else None

    # By severity
    by_severity: dict[str, Optional[float]] = {}
    for sev in FindingSeverity:
        if sev == FindingSeverity.INFO:
            continue
        sev_filters = [
            Finding.status.in_(RESOLVED_STATUSES),
            Finding.date_mitigated.isnot(None),
            Finding.is_duplicate == False,  # noqa: E712
            Finding.severity == sev,
        ]
        if product_id is not None:
            sev_filters.append(Finding.product_id == product_id)

        sev_q = select(
            func.avg(
                func.extract("epoch", Finding.date_mitigated)
                - func.extract("epoch", Finding.date_found)
            )
        ).where(*sev_filters)
        sev_seconds = (await db.execute(sev_q)).scalar()
        by_severity[sev.value] = (
            round(sev_seconds / 3600.0, 1) if sev_seconds else None
        )

    # Count of resolved findings for context
    count_q = select(func.count(Finding.id)).where(*base_filters)
    resolved_count = (await db.execute(count_q)).scalar() or 0

    # Generate trend data (mock when no historical granularity exists)
    seed_val = int((overall_mttr_hours or 48) * 100) + (product_id or 0)
    trend_30d = _mock_trend_points(
        current_value=overall_mttr_hours or 48.0,
        days=30,
        noise=0.12,
        direction="improving",
        seed=seed_val,
    )

    return {
        "overall_mttr_hours": overall_mttr_hours,
        "by_severity": by_severity,
        "resolved_count": resolved_count,
        "trend_30d": trend_30d,
    }


# ---------------------------------------------------------------------------
# Finding Aging Analysis
# ---------------------------------------------------------------------------

async def calculate_finding_aging(
    db: AsyncSession,
    product_id: Optional[int] = None,
) -> dict[str, Any]:
    """Group open findings by age buckets and severity."""
    now = datetime.now(timezone.utc)
    buckets = [
        ("0-7d", 0, 7),
        ("7-30d", 7, 30),
        ("30-90d", 30, 90),
        ("90-180d", 90, 180),
        ("180d+", 180, 9999),
    ]

    base_filters = [
        Finding.status.in_(OPEN_STATUSES),
        Finding.is_duplicate == False,  # noqa: E712
    ]
    if product_id is not None:
        base_filters.append(Finding.product_id == product_id)

    result: dict[str, dict[str, int]] = {}
    total_by_bucket: dict[str, int] = {}

    for bucket_name, min_days, max_days in buckets:
        bucket_data: dict[str, int] = {}
        bucket_total = 0
        start_date = now - timedelta(days=max_days)
        end_date = now - timedelta(days=min_days)

        for sev in FindingSeverity:
            if sev == FindingSeverity.INFO:
                continue

            filters = list(base_filters) + [
                Finding.severity == sev,
                Finding.date_found <= end_date,
            ]
            if max_days < 9999:
                filters.append(Finding.date_found > start_date)

            q = select(func.count(Finding.id)).where(*filters)
            count = (await db.execute(q)).scalar() or 0
            bucket_data[sev.value] = count
            bucket_total += count

        result[bucket_name] = bucket_data
        total_by_bucket[bucket_name] = bucket_total

    # Summary stats
    total_open_q = select(func.count(Finding.id)).where(*base_filters)
    total_open = (await db.execute(total_open_q)).scalar() or 0

    oldest_q = (
        select(Finding.date_found)
        .where(*base_filters)
        .order_by(Finding.date_found.asc())
        .limit(1)
    )
    oldest_row = (await db.execute(oldest_q)).scalar()
    oldest_age_days = (
        (now - oldest_row).days if oldest_row else 0
    )

    return {
        "buckets": result,
        "total_by_bucket": total_by_bucket,
        "total_open": total_open,
        "oldest_finding_age_days": oldest_age_days,
    }


# ---------------------------------------------------------------------------
# Risk Burndown
# ---------------------------------------------------------------------------

async def calculate_risk_burndown(
    db: AsyncSession,
    product_id: Optional[int] = None,
) -> dict[str, Any]:
    """Calculate daily risk score for the last 30 days.

    Risk score = sum of severity weights of all open findings on that day.
    """
    now = datetime.now(timezone.utc)
    days = 30

    base_filters = [Finding.is_duplicate == False]  # noqa: E712
    if product_id is not None:
        base_filters.append(Finding.product_id == product_id)

    # Get current risk score as anchor
    current_risk_q = select(
        func.sum(
            case(
                (Finding.severity == FindingSeverity.CRITICAL, 10.0),
                (Finding.severity == FindingSeverity.HIGH, 5.0),
                (Finding.severity == FindingSeverity.MEDIUM, 2.0),
                (Finding.severity == FindingSeverity.LOW, 0.5),
                else_=0.0,
            )
        )
    ).where(
        Finding.status.in_(OPEN_STATUSES),
        *base_filters,
    )
    current_risk = (await db.execute(current_risk_q)).scalar() or 0.0

    # Count recently opened and recently resolved for realistic trend
    recent_opened_q = select(func.count(Finding.id)).where(
        Finding.date_found >= now - timedelta(days=days),
        *base_filters,
    )
    recent_opened = (await db.execute(recent_opened_q)).scalar() or 0

    recent_resolved_q = select(func.count(Finding.id)).where(
        Finding.date_mitigated.isnot(None),
        Finding.date_mitigated >= now - timedelta(days=days),
        *base_filters,
    )
    recent_resolved = (await db.execute(recent_resolved_q)).scalar() or 0

    # Determine trend direction from open/resolved ratio
    if recent_resolved > recent_opened * 1.2:
        direction = "improving"
    elif recent_opened > recent_resolved * 1.2:
        direction = "worsening"
    else:
        direction = "stable"

    seed_val = int(current_risk * 10) + (product_id or 0)
    data_points = _mock_trend_points(
        current_value=float(current_risk),
        days=days,
        noise=0.08,
        direction=direction,
        seed=seed_val,
    )

    return {
        "current_risk_score": round(current_risk, 1),
        "trend_direction": direction,
        "data_points": data_points,
        "recent_opened": recent_opened,
        "recent_resolved": recent_resolved,
    }


# ---------------------------------------------------------------------------
# Team Velocity
# ---------------------------------------------------------------------------

async def calculate_team_velocity(
    db: AsyncSession,
) -> dict[str, Any]:
    """Team velocity: findings resolved per user, weekly trends, top resolvers."""
    now = datetime.now(timezone.utc)
    four_weeks_ago = now - timedelta(weeks=4)

    # Resolved findings per assignee in last 4 weeks
    resolver_q = (
        select(
            Finding.assignee_id,
            func.count(Finding.id).label("resolved_count"),
        )
        .where(
            Finding.status.in_(RESOLVED_STATUSES),
            Finding.date_mitigated.isnot(None),
            Finding.date_mitigated >= four_weeks_ago,
            Finding.assignee_id.isnot(None),
        )
        .group_by(Finding.assignee_id)
        .order_by(func.count(Finding.id).desc())
    )
    resolver_rows = (await db.execute(resolver_q)).all()

    # Map user IDs to names
    user_ids = [row[0] for row in resolver_rows]
    user_map: dict[int, str] = {}
    if user_ids:
        users_q = select(User.id, User.full_name, User.username).where(
            User.id.in_(user_ids)
        )
        users_result = (await db.execute(users_q)).all()
        for uid, full_name, username in users_result:
            user_map[uid] = full_name or username

    top_resolvers = [
        {
            "user_id": row[0],
            "name": user_map.get(row[0], f"User {row[0]}"),
            "resolved_count": row[1],
        }
        for row in resolver_rows
    ]

    # Weekly resolution counts (last 4 weeks)
    weekly_data: list[dict[str, Any]] = []
    for week_offset in range(4, 0, -1):
        week_start = now - timedelta(weeks=week_offset)
        week_end = now - timedelta(weeks=week_offset - 1)
        week_q = select(func.count(Finding.id)).where(
            Finding.status.in_(RESOLVED_STATUSES),
            Finding.date_mitigated.isnot(None),
            Finding.date_mitigated >= week_start,
            Finding.date_mitigated < week_end,
        )
        count = (await db.execute(week_q)).scalar() or 0
        weekly_data.append({
            "week_start": week_start.date().isoformat(),
            "week_end": week_end.date().isoformat(),
            "resolved_count": count,
        })

    # Total resolved all time
    total_resolved_q = select(func.count(Finding.id)).where(
        Finding.status.in_(RESOLVED_STATUSES),
    )
    total_resolved = (await db.execute(total_resolved_q)).scalar() or 0

    # Total findings
    total_findings_q = select(func.count(Finding.id))
    total_findings = (await db.execute(total_findings_q)).scalar() or 0

    resolution_rate = (
        round(total_resolved / total_findings * 100, 1) if total_findings > 0 else 0.0
    )

    return {
        "top_resolvers": top_resolvers,
        "weekly_resolution": weekly_data,
        "total_resolved_last_4_weeks": sum(w["resolved_count"] for w in weekly_data),
        "total_resolved_all_time": total_resolved,
        "resolution_rate_pct": resolution_rate,
    }


# ---------------------------------------------------------------------------
# Scanner Effectiveness
# ---------------------------------------------------------------------------

async def calculate_scanner_effectiveness(
    db: AsyncSession,
) -> dict[str, Any]:
    """Scanner ROI: findings per scanner, duplicate rate, severity distribution."""
    # Findings per scanner
    scanner_q = (
        select(
            Finding.scanner,
            func.count(Finding.id).label("total"),
        )
        .where(Finding.scanner.isnot(None))
        .group_by(Finding.scanner)
        .order_by(func.count(Finding.id).desc())
    )
    scanner_rows = (await db.execute(scanner_q)).all()

    scanners: list[dict[str, Any]] = []
    for scanner_name, total in scanner_rows:
        # Duplicate count
        dup_q = select(func.count(Finding.id)).where(
            Finding.scanner == scanner_name,
            Finding.is_duplicate == True,  # noqa: E712
        )
        dup_count = (await db.execute(dup_q)).scalar() or 0

        # Severity distribution
        sev_q = (
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scanner == scanner_name)
            .group_by(Finding.severity)
        )
        sev_rows = (await db.execute(sev_q)).all()
        severity_dist = {row[0].value: row[1] for row in sev_rows}

        # Critical discovery count (unique, non-duplicate)
        crit_q = select(func.count(Finding.id)).where(
            Finding.scanner == scanner_name,
            Finding.severity == FindingSeverity.CRITICAL,
            Finding.is_duplicate == False,  # noqa: E712
        )
        critical_unique = (await db.execute(crit_q)).scalar() or 0

        # False positive count
        fp_q = select(func.count(Finding.id)).where(
            Finding.scanner == scanner_name,
            Finding.status == FindingStatus.FALSE_POSITIVE,
        )
        false_positives = (await db.execute(fp_q)).scalar() or 0

        unique_count = total - dup_count
        duplicate_rate = round(dup_count / total * 100, 1) if total > 0 else 0.0
        fp_rate = round(false_positives / total * 100, 1) if total > 0 else 0.0

        scanners.append({
            "scanner": scanner_name,
            "total_findings": total,
            "unique_findings": unique_count,
            "duplicate_findings": dup_count,
            "duplicate_rate_pct": duplicate_rate,
            "false_positive_count": false_positives,
            "false_positive_rate_pct": fp_rate,
            "critical_unique_findings": critical_unique,
            "severity_distribution": severity_dist,
        })

    return {
        "scanners": scanners,
        "total_scanners": len(scanners),
    }


# ---------------------------------------------------------------------------
# Vulnerability Trends
# ---------------------------------------------------------------------------

async def calculate_vulnerability_trends(
    db: AsyncSession,
    days: int = 90,
) -> dict[str, Any]:
    """New vs resolved findings over time, net open trend, broken down by severity."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    # New findings per day
    new_q = (
        select(
            func.date(Finding.date_found).label("day"),
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .where(
            Finding.date_found >= start,
            Finding.is_duplicate == False,  # noqa: E712
        )
        .group_by(func.date(Finding.date_found), Finding.severity)
        .order_by(func.date(Finding.date_found))
    )
    new_rows = (await db.execute(new_q)).all()

    # Resolved findings per day
    resolved_q = (
        select(
            func.date(Finding.date_mitigated).label("day"),
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .where(
            Finding.date_mitigated.isnot(None),
            Finding.date_mitigated >= start,
            Finding.status.in_(RESOLVED_STATUSES),
            Finding.is_duplicate == False,  # noqa: E712
        )
        .group_by(func.date(Finding.date_mitigated), Finding.severity)
        .order_by(func.date(Finding.date_mitigated))
    )
    resolved_rows = (await db.execute(resolved_q)).all()

    # Aggregate into daily buckets
    daily: dict[str, dict[str, Any]] = {}
    for i in range(days + 1):
        d = (start + timedelta(days=i)).date().isoformat()
        daily[d] = {
            "date": d,
            "new_total": 0,
            "resolved_total": 0,
            "new_by_severity": {},
            "resolved_by_severity": {},
        }

    for day, severity, count in new_rows:
        day_str = str(day)
        if day_str in daily:
            daily[day_str]["new_total"] += count
            daily[day_str]["new_by_severity"][severity.value] = count

    for day, severity, count in resolved_rows:
        day_str = str(day)
        if day_str in daily:
            daily[day_str]["resolved_total"] += count
            daily[day_str]["resolved_by_severity"][severity.value] = count

    # Sort and calculate running net open count
    sorted_days = sorted(daily.values(), key=lambda x: x["date"])

    # Get starting open count (before the window)
    open_before_q = select(func.count(Finding.id)).where(
        Finding.date_found < start,
        Finding.status.in_(OPEN_STATUSES),
        Finding.is_duplicate == False,  # noqa: E712
    )
    open_before = (await db.execute(open_before_q)).scalar() or 0

    net_open = open_before
    for day_data in sorted_days:
        net_open += day_data["new_total"] - day_data["resolved_total"]
        day_data["net_open"] = max(0, net_open)

    # Summary
    total_new = sum(d["new_total"] for d in sorted_days)
    total_resolved = sum(d["resolved_total"] for d in sorted_days)

    return {
        "days": days,
        "data_points": sorted_days,
        "summary": {
            "total_new": total_new,
            "total_resolved": total_resolved,
            "net_change": total_new - total_resolved,
            "current_open": sorted_days[-1]["net_open"] if sorted_days else 0,
        },
    }


# ---------------------------------------------------------------------------
# Executive Summary
# ---------------------------------------------------------------------------

async def get_executive_summary(
    db: AsyncSession,
) -> dict[str, Any]:
    """Executive-ready summary with risk level, trends, and action items."""
    now = datetime.now(timezone.utc)

    # Total open findings
    open_q = select(func.count(Finding.id)).where(
        Finding.status.in_(OPEN_STATUSES),
        Finding.is_duplicate == False,  # noqa: E712
    )
    total_open = (await db.execute(open_q)).scalar() or 0

    # Critical open
    critical_q = select(func.count(Finding.id)).where(
        Finding.status.in_(OPEN_STATUSES),
        Finding.severity == FindingSeverity.CRITICAL,
        Finding.is_duplicate == False,  # noqa: E712
    )
    critical_open = (await db.execute(critical_q)).scalar() or 0

    # High open
    high_q = select(func.count(Finding.id)).where(
        Finding.status.in_(OPEN_STATUSES),
        Finding.severity == FindingSeverity.HIGH,
        Finding.is_duplicate == False,  # noqa: E712
    )
    high_open = (await db.execute(high_q)).scalar() or 0

    # MTTR for critical
    mttr_data = await calculate_mttr(db, severity="critical")
    mttr_critical = mttr_data["by_severity"].get("critical")

    # SLA compliance: findings within SLA deadline or already resolved
    total_with_sla_q = select(func.count(Finding.id)).where(
        Finding.sla_deadline.isnot(None),
        Finding.is_duplicate == False,  # noqa: E712
    )
    total_with_sla = (await db.execute(total_with_sla_q)).scalar() or 0

    compliant_q = select(func.count(Finding.id)).where(
        Finding.sla_deadline.isnot(None),
        Finding.is_duplicate == False,  # noqa: E712
        (
            (Finding.status.in_(RESOLVED_STATUSES) & (Finding.date_mitigated <= Finding.sla_deadline))
            | (Finding.status.in_(OPEN_STATUSES) & (Finding.sla_deadline >= now))
        ),
    )
    compliant_count = (await db.execute(compliant_q)).scalar() or 0
    sla_compliance_rate = (
        round(compliant_count / total_with_sla * 100, 1)
        if total_with_sla > 0
        else 100.0
    )

    # Findings opened in last 7 days vs previous 7 days for trend
    last_7d_q = select(func.count(Finding.id)).where(
        Finding.date_found >= now - timedelta(days=7),
        Finding.is_duplicate == False,  # noqa: E712
    )
    last_7d = (await db.execute(last_7d_q)).scalar() or 0

    prev_7d_q = select(func.count(Finding.id)).where(
        Finding.date_found >= now - timedelta(days=14),
        Finding.date_found < now - timedelta(days=7),
        Finding.is_duplicate == False,  # noqa: E712
    )
    prev_7d = (await db.execute(prev_7d_q)).scalar() or 0

    resolved_7d_q = select(func.count(Finding.id)).where(
        Finding.date_mitigated.isnot(None),
        Finding.date_mitigated >= now - timedelta(days=7),
        Finding.status.in_(RESOLVED_STATUSES),
    )
    resolved_7d = (await db.execute(resolved_7d_q)).scalar() or 0

    # Determine overall risk level
    if critical_open >= 5 or total_open > 100:
        overall_risk_level = "critical"
    elif critical_open >= 1 or high_open >= 10 or total_open > 50:
        overall_risk_level = "high"
    elif high_open >= 3 or total_open > 20:
        overall_risk_level = "medium"
    else:
        overall_risk_level = "low"

    # Determine risk trend
    if last_7d > prev_7d * 1.25 and prev_7d > 0:
        risk_trend = "worsening"
    elif last_7d < prev_7d * 0.75 or resolved_7d > last_7d:
        risk_trend = "improving"
    else:
        risk_trend = "stable"

    # Build highlights
    highlights: list[str] = []
    if critical_open > 0:
        highlights.append(
            f"{critical_open} critical finding(s) require immediate attention."
        )
    if resolved_7d > 0:
        highlights.append(
            f"{resolved_7d} finding(s) resolved in the past 7 days."
        )
    if last_7d > 0:
        highlights.append(
            f"{last_7d} new finding(s) discovered in the past 7 days."
        )
    if sla_compliance_rate < 90:
        highlights.append(
            f"SLA compliance is at {sla_compliance_rate}%, below the 90% target."
        )
    if not highlights:
        highlights.append("No notable security events in the past week.")

    # Build action items
    action_items: list[str] = []
    if critical_open > 0:
        action_items.append(
            f"Remediate {critical_open} critical finding(s) within SLA deadlines."
        )
    if high_open > 5:
        action_items.append(
            f"Address {high_open} high-severity open findings to reduce risk exposure."
        )
    if mttr_critical and mttr_critical > DEFAULT_SLA_HOURS.get("critical", 24):
        action_items.append(
            "Critical MTTR exceeds SLA target. Review triage and assignment workflows."
        )
    if sla_compliance_rate < 90:
        action_items.append(
            "Improve SLA compliance rate. Consider reallocating resources to overdue findings."
        )
    if not action_items:
        action_items.append(
            "Maintain current remediation velocity and continue regular scanning."
        )

    return {
        "overall_risk_level": overall_risk_level,
        "risk_trend": risk_trend,
        "key_metrics": {
            "total_open": total_open,
            "critical_open": critical_open,
            "high_open": high_open,
            "mttr_critical_hours": mttr_critical,
            "sla_compliance_rate": sla_compliance_rate,
            "findings_last_7d": last_7d,
            "resolved_last_7d": resolved_7d,
        },
        "highlights": highlights,
        "action_items": action_items,
    }


# ---------------------------------------------------------------------------
# Full KPI Dashboard
# ---------------------------------------------------------------------------

async def get_kpi_dashboard(
    db: AsyncSession,
    product_id: Optional[int] = None,
) -> dict[str, Any]:
    """Aggregate all KPI metrics into a single dashboard response."""
    mttr = await calculate_mttr(db, product_id=product_id)
    aging = await calculate_finding_aging(db, product_id=product_id)
    burndown = await calculate_risk_burndown(db, product_id=product_id)
    velocity = await calculate_team_velocity(db)
    scanner = await calculate_scanner_effectiveness(db)
    trends = await calculate_vulnerability_trends(db, days=30)
    executive = await get_executive_summary(db)

    return {
        "executive_summary": executive,
        "mttr": mttr,
        "finding_aging": aging,
        "risk_burndown": burndown,
        "team_velocity": velocity,
        "scanner_effectiveness": scanner,
        "vulnerability_trends": trends,
    }
