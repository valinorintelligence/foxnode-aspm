import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.product import Product

logger = logging.getLogger(__name__)

# Severity weights used for penalty calculation
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.0,
}

# Grade thresholds (inclusive lower bound)
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]

# Estimated LOC per product (placeholder until real LOC tracking exists)
DEFAULT_LOC_ESTIMATE = 50_000


class ScorecardService:
    """Security scoring engine that produces letter-grade scorecards."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _grade_from_score(score: float) -> str:
        """Return a letter grade for a numeric score."""
        clamped = max(0.0, min(100.0, score))
        for threshold, grade in GRADE_THRESHOLDS:
            if clamped >= threshold:
                return grade
        return "F"

    @staticmethod
    def _trend_from_history(history: list[dict[str, Any]]) -> str:
        """Determine trend direction from a list of historical data points."""
        if len(history) < 2:
            return "stable"
        recent = [p["score"] for p in history[-7:]]
        older = [p["score"] for p in history[:7]]
        avg_recent = sum(recent) / len(recent)
        avg_older = sum(older) / len(older)
        diff = avg_recent - avg_older
        if diff > 3:
            return "improving"
        if diff < -3:
            return "declining"
        return "stable"

    # ------------------------------------------------------------------
    # Core scoring
    # ------------------------------------------------------------------

    async def _severity_counts(
        self, db: AsyncSession, product_id: int
    ) -> dict[str, int]:
        """Return open (non-duplicate) finding counts keyed by severity value."""
        query = (
            select(Finding.severity, func.count(Finding.id))
            .where(
                Finding.product_id == product_id,
                Finding.is_duplicate == False,  # noqa: E712
                Finding.status.in_([FindingStatus.ACTIVE, FindingStatus.VERIFIED]),
            )
            .group_by(Finding.severity)
        )
        result = await db.execute(query)
        counts: dict[str, int] = {}
        for row in result.all():
            counts[row[0].value] = row[1]
        return counts

    async def _total_finding_counts(
        self, db: AsyncSession, product_id: int
    ) -> dict[str, int]:
        """Return total finding counts by status for a product."""
        query = (
            select(Finding.status, func.count(Finding.id))
            .where(
                Finding.product_id == product_id,
                Finding.is_duplicate == False,  # noqa: E712
            )
            .group_by(Finding.status)
        )
        result = await db.execute(query)
        return {row[0].value: row[1] for row in result.all()}

    async def _mean_time_to_remediate(
        self, db: AsyncSession, product_id: int
    ) -> Optional[float]:
        """Return the average days between date_found and date_mitigated."""
        query = (
            select(
                func.avg(
                    func.extract("epoch", Finding.date_mitigated)
                    - func.extract("epoch", Finding.date_found)
                )
            )
            .where(
                Finding.product_id == product_id,
                Finding.date_mitigated.isnot(None),
                Finding.is_duplicate == False,  # noqa: E712
            )
        )
        result = (await db.execute(query)).scalar()
        if result is None:
            return None
        return round(result / 86400.0, 1)  # seconds -> days

    async def _false_positive_ratio(
        self, db: AsyncSession, product_id: int
    ) -> float:
        """Return the fraction of findings marked as false positive."""
        total_q = (
            select(func.count(Finding.id))
            .where(
                Finding.product_id == product_id,
                Finding.is_duplicate == False,  # noqa: E712
            )
        )
        total = (await db.execute(total_q)).scalar() or 0
        if total == 0:
            return 0.0

        fp_q = (
            select(func.count(Finding.id))
            .where(
                Finding.product_id == product_id,
                Finding.is_duplicate == False,  # noqa: E712
                Finding.status == FindingStatus.FALSE_POSITIVE,
            )
        )
        fp_count = (await db.execute(fp_q)).scalar() or 0
        return round(fp_count / total, 4)

    async def _mitigated_percentage(
        self, db: AsyncSession, product_id: int
    ) -> float:
        """Return the percentage of findings that have been mitigated."""
        total_q = (
            select(func.count(Finding.id))
            .where(
                Finding.product_id == product_id,
                Finding.is_duplicate == False,  # noqa: E712
            )
        )
        total = (await db.execute(total_q)).scalar() or 0
        if total == 0:
            return 100.0

        mitigated_q = (
            select(func.count(Finding.id))
            .where(
                Finding.product_id == product_id,
                Finding.is_duplicate == False,  # noqa: E712
                Finding.status == FindingStatus.MITIGATED,
            )
        )
        mitigated = (await db.execute(mitigated_q)).scalar() or 0
        return round((mitigated / total) * 100.0, 1)

    async def calculate_product_score(
        self, db: AsyncSession, product_id: int
    ) -> dict[str, Any]:
        """Calculate and return the full scorecard for a single product.

        Formula:
            - Start at 100
            - Subtract weighted penalty per open finding:
              penalty = sum(count * weight) / (LOC_estimate / 1000)
            - Bonus for remediation velocity:
              +5 if MTTR < 7 days, +2 if < 14 days
            - Bonus for high mitigated percentage:
              + mitigated_pct * 0.1 (max +10)

        Returns:
            Dict with score, grade, trend, breakdown, and recommendations.
        """
        severity_counts = await self._severity_counts(db, product_id)
        status_counts = await self._total_finding_counts(db, product_id)
        mttr = await self._mean_time_to_remediate(db, product_id)
        fp_ratio = await self._false_positive_ratio(db, product_id)
        mitigated_pct = await self._mitigated_percentage(db, product_id)

        # --- Weighted penalty ---
        loc_factor = DEFAULT_LOC_ESTIMATE / 1000.0
        weighted_sum = sum(
            severity_counts.get(sev, 0) * weight
            for sev, weight in SEVERITY_WEIGHTS.items()
        )
        density_penalty = min(weighted_sum / loc_factor * 10.0, 80.0)

        score = 100.0 - density_penalty

        # --- MTTR bonus ---
        mttr_bonus = 0.0
        if mttr is not None:
            if mttr < 7:
                mttr_bonus = 5.0
            elif mttr < 14:
                mttr_bonus = 2.0
        score += mttr_bonus

        # --- Mitigation bonus ---
        mitigation_bonus = min(mitigated_pct * 0.1, 10.0)
        score += mitigation_bonus

        score = max(0.0, min(100.0, round(score, 1)))
        grade = self._grade_from_score(score)

        # --- Historical trend (mock) ---
        history = self._generate_mock_history(score)
        trend = self._trend_from_history(history)

        # --- Recommendations ---
        recommendations = self._build_recommendations(
            severity_counts, mttr, fp_ratio, mitigated_pct
        )

        breakdown = {
            "open_findings_by_severity": severity_counts,
            "findings_by_status": status_counts,
            "density_penalty": round(density_penalty, 2),
            "mttr_days": mttr,
            "mttr_bonus": mttr_bonus,
            "false_positive_ratio": fp_ratio,
            "mitigated_percentage": mitigated_pct,
            "mitigation_bonus": round(mitigation_bonus, 2),
            "loc_estimate": DEFAULT_LOC_ESTIMATE,
        }

        return {
            "product_id": product_id,
            "score": score,
            "grade": grade,
            "trend": trend,
            "breakdown": breakdown,
            "recommendations": recommendations,
            "history": history,
        }

    # ------------------------------------------------------------------
    # Org-wide & leaderboard
    # ------------------------------------------------------------------

    async def calculate_org_overview(
        self, db: AsyncSession
    ) -> dict[str, Any]:
        """Calculate org-wide score and leaderboard across all products."""
        products_result = await db.execute(select(Product).order_by(Product.name))
        products = products_result.scalars().all()

        product_scores: list[dict[str, Any]] = []
        total_weight = 0.0
        weighted_score_sum = 0.0

        criticality_weights = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0,
        }

        for product in products:
            card = await self.calculate_product_score(db, product.id)
            weight = criticality_weights.get(product.business_criticality, 2.0)
            weighted_score_sum += card["score"] * weight
            total_weight += weight
            product_scores.append({
                "product_id": product.id,
                "product_name": product.name,
                "business_criticality": product.business_criticality,
                "score": card["score"],
                "grade": card["grade"],
                "trend": card["trend"],
            })

        org_score = round(weighted_score_sum / total_weight, 1) if total_weight > 0 else 100.0
        org_grade = self._grade_from_score(org_score)

        # Leaderboard: sorted best-to-worst
        leaderboard = sorted(product_scores, key=lambda p: p["score"], reverse=True)

        # Org-level history (mock)
        org_history = self._generate_mock_history(org_score)
        org_trend = self._trend_from_history(org_history)

        return {
            "org_score": org_score,
            "org_grade": org_grade,
            "org_trend": org_trend,
            "total_products": len(products),
            "product_scores": product_scores,
            "leaderboard": leaderboard,
            "history": org_history,
        }

    async def get_trend_data(
        self, db: AsyncSession, product_id: Optional[int] = None
    ) -> dict[str, Any]:
        """Return score trend data (last 30 days) for charting.

        If *product_id* is provided, returns trend for that product.
        Otherwise, returns the org-wide trend.
        """
        if product_id is not None:
            card = await self.calculate_product_score(db, product_id)
            return {
                "product_id": product_id,
                "data_points": card["history"],
            }

        overview = await self.calculate_org_overview(db)
        return {
            "product_id": None,
            "data_points": overview["history"],
        }

    # ------------------------------------------------------------------
    # Mock history generator
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_mock_history(
        current_score: float, days: int = 30
    ) -> list[dict[str, Any]]:
        """Generate plausible mock historical score data points.

        Seeds the random generator deterministically based on the current
        score so that repeated calls return consistent results.
        """
        rng = random.Random(int(current_score * 100))
        today = datetime.now(timezone.utc).date()
        points: list[dict[str, Any]] = []
        score = max(0.0, min(100.0, current_score - rng.uniform(-8, 12)))

        for i in range(days):
            date = today - timedelta(days=days - 1 - i)
            drift = rng.uniform(-2.0, 2.5)
            score = max(0.0, min(100.0, score + drift))
            points.append({
                "date": date.isoformat(),
                "score": round(score, 1),
                "grade": ScorecardService._grade_from_score(score),
            })

        # Ensure the last point matches the current score
        if points:
            points[-1]["score"] = current_score
            points[-1]["grade"] = ScorecardService._grade_from_score(current_score)

        return points

    # ------------------------------------------------------------------
    # Recommendations engine
    # ------------------------------------------------------------------

    @staticmethod
    def _build_recommendations(
        severity_counts: dict[str, int],
        mttr: Optional[float],
        fp_ratio: float,
        mitigated_pct: float,
    ) -> list[str]:
        """Build actionable recommendations based on scorecard metrics."""
        recs: list[str] = []

        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)

        if critical > 0:
            recs.append(
                f"Prioritize {critical} critical finding(s) for immediate remediation."
            )
        if high > 5:
            recs.append(
                f"Reduce the {high} open high-severity findings to lower risk exposure."
            )

        if mttr is not None and mttr > 30:
            recs.append(
                f"Mean time to remediate is {mttr} days. Target under 14 days for high/critical findings."
            )
        elif mttr is None:
            recs.append(
                "No remediated findings yet. Begin tracking remediation timelines."
            )

        if fp_ratio > 0.3:
            recs.append(
                "Over 30% of findings are false positives. Tune scanner rules to reduce noise."
            )

        if mitigated_pct < 50:
            recs.append(
                f"Only {mitigated_pct}% of findings are mitigated. Increase remediation efforts."
            )

        if not recs:
            recs.append("Security posture is strong. Continue regular scanning and remediation.")

        return recs
