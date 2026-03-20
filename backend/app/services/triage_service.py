import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.models.finding import Finding, FindingSeverity, FindingStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, float] = {
    FindingSeverity.CRITICAL.value: 1.0,
    FindingSeverity.HIGH.value: 0.8,
    FindingSeverity.MEDIUM.value: 0.5,
    FindingSeverity.LOW.value: 0.2,
    FindingSeverity.INFO.value: 0.05,
}

CRITICALITY_MULTIPLIERS: dict[str, float] = {
    "critical": 1.3,
    "high": 1.15,
    "medium": 1.0,
    "low": 0.85,
    "none": 0.7,
}

# File-path patterns that indicate security-sensitive code.
HIGH_VALUE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"(^|/)auth", re.IGNORECASE),
    re.compile(r"(^|/)login", re.IGNORECASE),
    re.compile(r"(^|/)crypt", re.IGNORECASE),
    re.compile(r"(^|/)secur", re.IGNORECASE),
    re.compile(r"(^|/)token", re.IGNORECASE),
    re.compile(r"(^|/)session", re.IGNORECASE),
    re.compile(r"(^|/)password", re.IGNORECASE),
    re.compile(r"(^|/)payment", re.IGNORECASE),
    re.compile(r"(^|/)admin", re.IGNORECASE),
    re.compile(r"(^|/)middleware", re.IGNORECASE),
    re.compile(r"(^|/)api[/\\]", re.IGNORECASE),
]

# Patterns that strongly suggest a false positive.
FALSE_POSITIVE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"(^|/)(test|tests|__tests__|spec|specs|test_|_test\.)", re.IGNORECASE),
    re.compile(r"(^|/)node_modules/", re.IGNORECASE),
    re.compile(r"(^|/)vendor/", re.IGNORECASE),
    re.compile(r"(^|/)(example|examples|sample|samples|demo|demos)/", re.IGNORECASE),
    re.compile(r"(^|/)fixtures?/", re.IGNORECASE),
    re.compile(r"(^|/)mock(s|data)?/", re.IGNORECASE),
    re.compile(r"\.(test|spec|stories)\.(js|ts|jsx|tsx|py|rb)$", re.IGNORECASE),
    re.compile(r"(^|/)\.storybook/", re.IGNORECASE),
    re.compile(r"(^|/)docs?/", re.IGNORECASE),
    re.compile(r"(^|/)dist/", re.IGNORECASE),
    re.compile(r"(^|/)build/", re.IGNORECASE),
    re.compile(r"(^|/)third[_-]?party/", re.IGNORECASE),
]

FALSE_POSITIVE_TITLE_PATTERNS: list[re.Pattern] = [
    re.compile(r"comment(ed)?[\s_-]?(out|block)", re.IGNORECASE),
    re.compile(r"TODO|FIXME|HACK", re.IGNORECASE),
    re.compile(r"example[\s_-]?code", re.IGNORECASE),
    re.compile(r"placeholder", re.IGNORECASE),
    re.compile(r"template[\s_-]?literal", re.IGNORECASE),
]

# Days thresholds for age scoring.
AGE_BRACKETS: list[tuple[int, float]] = [
    (180, 1.0),   # older than 6 months
    (90, 0.85),   # older than 3 months
    (30, 0.65),   # older than 1 month
    (7, 0.4),     # older than 1 week
    (0, 0.2),     # very recent
]


# ---------------------------------------------------------------------------
# Result data classes
# ---------------------------------------------------------------------------

@dataclass
class TriageResult:
    finding_id: int
    score: float                        # 0-100
    priority: str                       # immediate / next_sprint / backlog / monitor
    false_positive_likelihood: float    # 0.0-1.0
    reasoning: list[str] = field(default_factory=list)
    suggested_grouping: Optional[str] = None

    # Extra context populated by the API layer
    title: str = ""
    severity: str = ""
    file_path: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "score": round(self.score, 2),
            "priority": self.priority,
            "false_positive_likelihood": round(self.false_positive_likelihood, 3),
            "reasoning": self.reasoning,
            "suggested_grouping": self.suggested_grouping,
            "title": self.title,
            "severity": self.severity,
            "file_path": self.file_path,
        }


@dataclass
class TriageSummary:
    product_id: int
    total_findings: int
    counts_by_priority: dict[str, int]
    top_false_positive_candidates: list[dict]
    grouped_findings: dict[str, list[int]]

    def to_dict(self) -> dict:
        return {
            "product_id": self.product_id,
            "total_findings": self.total_findings,
            "counts_by_priority": self.counts_by_priority,
            "top_false_positive_candidates": self.top_false_positive_candidates,
            "grouped_findings": self.grouped_findings,
        }


# ---------------------------------------------------------------------------
# Triage engine
# ---------------------------------------------------------------------------

class TriageService:
    """Offline, pattern-matching and scoring-based triage engine."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def triage_finding(
        self,
        finding: Finding,
        product_criticality: str = "medium",
    ) -> TriageResult:
        """Analyse a single finding and return a TriageResult."""

        reasoning: list[str] = []
        score = 0.0

        # 1. Severity weight (0-30 points)
        severity_value = (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        )
        sev_weight = SEVERITY_WEIGHTS.get(severity_value, 0.3)
        sev_points = sev_weight * 30
        score += sev_points
        reasoning.append(f"Severity '{severity_value}' contributes {sev_points:.1f} points")

        # 2. CVSS score (0-25 points)
        if finding.cvss_score is not None and finding.cvss_score > 0:
            cvss_points = (finding.cvss_score / 10.0) * 25
            score += cvss_points
            reasoning.append(f"CVSS {finding.cvss_score} contributes {cvss_points:.1f} points")
        else:
            # Infer a baseline from severity when CVSS is absent.
            inferred = sev_weight * 15
            score += inferred
            reasoning.append(f"No CVSS score; inferred {inferred:.1f} points from severity")

        # 3. CVE presence (0-5 points)
        if finding.cve:
            score += 5
            reasoning.append("Known CVE identifier present (+5)")

        # 4. Product criticality multiplier
        multiplier = CRITICALITY_MULTIPLIERS.get(product_criticality, 1.0)
        if multiplier != 1.0:
            score *= multiplier
            reasoning.append(
                f"Product criticality '{product_criticality}' applies {multiplier}x multiplier"
            )

        # 5. High-value file path (0-10 points)
        file_path = finding.file_path or ""
        hv_boost = self._high_value_path_score(file_path)
        if hv_boost > 0:
            score += hv_boost
            reasoning.append(f"Security-sensitive file path (+{hv_boost})")

        # 6. Age of finding (0-10 points)
        age_points = self._age_score(finding.date_found)
        score += age_points
        reasoning.append(f"Finding age contributes {age_points:.1f} points")

        # 7. Duplicate penalty
        if finding.is_duplicate:
            score *= 0.4
            reasoning.append("Duplicate finding (score reduced to 40%)")

        # Clamp to 0-100
        score = max(0.0, min(100.0, score))

        # False-positive analysis
        fp_likelihood = self._false_positive_likelihood(finding)

        # Determine priority
        priority = self._determine_priority(score, fp_likelihood)

        # Suggested grouping key
        grouping = self._suggest_grouping(finding)

        severity_str = (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        )

        return TriageResult(
            finding_id=finding.id,
            score=score,
            priority=priority,
            false_positive_likelihood=fp_likelihood,
            reasoning=reasoning,
            suggested_grouping=grouping,
            title=finding.title or "",
            severity=severity_str,
            file_path=finding.file_path or "",
        )

    def triage_findings(
        self,
        findings: list[Finding],
        product_criticality: str = "medium",
    ) -> list[TriageResult]:
        """Triage a batch of findings and return results sorted by score descending."""
        results = [
            self.triage_finding(f, product_criticality=product_criticality)
            for f in findings
        ]
        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def build_summary(
        self,
        product_id: int,
        results: list[TriageResult],
    ) -> TriageSummary:
        """Aggregate triage results into a product-level summary."""
        counts: dict[str, int] = defaultdict(int)
        grouped: dict[str, list[int]] = defaultdict(list)

        for r in results:
            counts[r.priority] += 1
            if r.suggested_grouping:
                grouped[r.suggested_grouping].append(r.finding_id)

        # Top false-positive candidates (likelihood >= 0.5), capped at 20
        fp_candidates = sorted(
            [r for r in results if r.false_positive_likelihood >= 0.5],
            key=lambda r: r.false_positive_likelihood,
            reverse=True,
        )[:20]

        return TriageSummary(
            product_id=product_id,
            total_findings=len(results),
            counts_by_priority=dict(counts),
            top_false_positive_candidates=[
                {
                    "finding_id": c.finding_id,
                    "false_positive_likelihood": round(c.false_positive_likelihood, 3),
                    "score": round(c.score, 2),
                    "reasoning": c.reasoning,
                    "title": c.title,
                    "severity": c.severity,
                }
                for c in fp_candidates
            ],
            grouped_findings=dict(grouped),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _high_value_path_score(file_path: str) -> float:
        """Return bonus points if the path matches security-sensitive patterns."""
        if not file_path:
            return 0.0
        for pattern in HIGH_VALUE_PATH_PATTERNS:
            if pattern.search(file_path):
                return 10.0
        return 0.0

    @staticmethod
    def _age_score(date_found: Optional[datetime]) -> float:
        """Older findings score higher because they have been exposed longer."""
        if date_found is None:
            return 5.0  # unknown age, use midpoint
        now = datetime.now(timezone.utc)
        # Ensure date_found is timezone-aware for comparison.
        if date_found.tzinfo is None:
            date_found = date_found.replace(tzinfo=timezone.utc)
        age_days = (now - date_found).days
        for threshold, weight in AGE_BRACKETS:
            if age_days >= threshold:
                return weight * 10
        return 2.0

    @staticmethod
    def _false_positive_likelihood(finding: Finding) -> float:
        """Return a 0-1 score indicating how likely the finding is a false positive."""
        signals: list[float] = []

        file_path = finding.file_path or ""
        title = finding.title or ""

        # Already marked as false positive or duplicate
        if finding.status == FindingStatus.FALSE_POSITIVE:
            return 1.0
        if finding.is_duplicate:
            signals.append(0.3)

        # Path-based signals
        for pattern in FALSE_POSITIVE_PATH_PATTERNS:
            if pattern.search(file_path):
                signals.append(0.6)
                break

        # Title-based signals
        for pattern in FALSE_POSITIVE_TITLE_PATTERNS:
            if pattern.search(title):
                signals.append(0.4)
                break

        # Info-severity findings from SAST scanners are frequently false positives
        severity_value = (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        )
        if severity_value == FindingSeverity.INFO.value:
            signals.append(0.25)

        # No CVE and no CVSS suggest a heuristic-only finding
        if not finding.cve and not finding.cvss_score:
            signals.append(0.15)

        if not signals:
            return 0.0

        # Combine using "noisy-OR" so multiple weak signals add up.
        combined = 1.0
        for s in signals:
            combined *= (1.0 - s)
        return round(1.0 - combined, 4)

    @staticmethod
    def _determine_priority(score: float, fp_likelihood: float) -> str:
        """Map triage score and false-positive likelihood to a remediation priority."""
        # High FP likelihood demotes priority regardless of score.
        if fp_likelihood >= 0.7:
            return "monitor"

        if score >= 75:
            return "immediate"
        if score >= 50:
            return "next_sprint"
        if score >= 25:
            return "backlog"
        return "monitor"

    @staticmethod
    def _suggest_grouping(finding: Finding) -> Optional[str]:
        """Suggest a grouping key so related findings can be clustered."""
        # Prefer CWE grouping
        if finding.cwe:
            return f"CWE-{finding.cwe}"

        # Fall back to component grouping
        if finding.component:
            return f"component:{finding.component}"

        # Fall back to directory grouping
        if finding.file_path:
            directory = os.path.dirname(finding.file_path)
            if directory:
                return f"path:{directory}"

        return None
