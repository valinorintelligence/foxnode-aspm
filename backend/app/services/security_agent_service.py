"""
AI Security Agent — autonomous security-posture analysis engine.

All analysis is performed using real database queries against Finding and
Product models.  No external AI/LLM calls are made; the agent relies on
pattern matching, statistical aggregation, and heuristic reasoning.
"""

import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.product import Product

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

ATTACK_CHAIN_TEMPLATES = [
    {
        "name": "Account Takeover",
        "required_cwes": [{79, 80}, {384}, {613}],  # XSS, Session Fixation, Improper Session Expiry
        "required_titles": [
            [re.compile(r"xss|cross.?site.?script", re.I)],
            [re.compile(r"session.?fix|session.?hijack|session.?manag", re.I)],
        ],
        "description": "XSS combined with session management weaknesses can lead to full account takeover.",
        "base_risk": 9.2,
    },
    {
        "name": "Data Breach via SQL Injection",
        "required_cwes": [{89}, {200, 209, 532}],  # SQLi, Info Exposure
        "required_titles": [
            [re.compile(r"sql.?inject", re.I)],
            [re.compile(r"sensitive.?data|info.?(exposure|leak|disclos)", re.I)],
        ],
        "description": "SQL Injection paired with sensitive data exposure creates a direct path to data breach.",
        "base_risk": 9.5,
    },
    {
        "name": "Infrastructure Compromise",
        "required_cwes": [{918}, {16, 250}],  # SSRF, Config / Privilege
        "required_titles": [
            [re.compile(r"ssrf|server.?side.?request", re.I)],
            [re.compile(r"misconfig|cloud|infra|privilege|iam", re.I)],
        ],
        "description": "SSRF with cloud or infrastructure misconfiguration can lead to full infrastructure compromise.",
        "base_risk": 9.0,
    },
    {
        "name": "Remote Code Execution",
        "required_cwes": [{94, 78, 77}, {434}],  # Injection / OS Command, Unrestricted Upload
        "required_titles": [
            [re.compile(r"(code|command|os).?inject|rce|remote.?code", re.I)],
            [re.compile(r"file.?upload|unrestrict", re.I)],
        ],
        "description": "Code injection combined with unrestricted file upload enables remote code execution.",
        "base_risk": 9.8,
    },
    {
        "name": "Privilege Escalation",
        "required_cwes": [{862, 863}, {285, 269}],  # Missing AuthZ, Improper AuthZ / Privilege
        "required_titles": [
            [re.compile(r"(missing|broken).?auth|idor|insecure.?direct", re.I)],
            [re.compile(r"privilege|escalat|access.?control|role", re.I)],
        ],
        "description": "Broken access controls combined with privilege management flaws allow vertical privilege escalation.",
        "base_risk": 8.5,
    },
    {
        "name": "Supply Chain Attack",
        "required_cwes": [{829, 506}, {1104}],  # Untrusted Components / Malicious, Unmaintained
        "required_titles": [
            [re.compile(r"vulnerable.?dep|outdated.?(lib|component|package)", re.I)],
            [re.compile(r"known.?vuln|cve-|supply.?chain", re.I)],
        ],
        "description": "Vulnerable or outdated dependencies create supply chain risk vectors.",
        "base_risk": 7.5,
    },
]

COMPLIANCE_FRAMEWORKS = {
    "OWASP Top 10": {
        "A01 - Broken Access Control": [862, 863, 639, 285, 269],
        "A02 - Cryptographic Failures": [327, 328, 261, 319, 326],
        "A03 - Injection": [79, 89, 77, 78, 94],
        "A04 - Insecure Design": [209, 256, 501, 522],
        "A05 - Security Misconfiguration": [16, 611, 1004, 942],
        "A06 - Vulnerable Components": [1104, 829, 506],
        "A07 - Auth Failures": [287, 384, 613, 620, 640],
        "A08 - Data Integrity Failures": [345, 502, 829, 915],
        "A09 - Logging Failures": [532, 778, 117],
        "A10 - SSRF": [918],
    },
    "SANS Top 25": {
        "Out-of-bounds Write": [787],
        "XSS": [79],
        "SQL Injection": [89],
        "Use After Free": [416],
        "OS Command Injection": [78],
        "Improper Input Validation": [20],
        "Path Traversal": [22],
        "CSRF": [352],
    },
}

# Chat question patterns
QUESTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"top\s+risk|biggest\s+risk|worst|most\s+(critical|severe|dangerous)", re.I), "top_risks"),
    (re.compile(r"how\s+many\s+(critical|high|medium|low|info|finding|vuln)", re.I), "counts"),
    (re.compile(r"what\s+should\s+i\s+fix|priorit|fix\s+first|where\s+to\s+start|remediat", re.I), "fix_first"),
    (re.compile(r"compliance|owasp|sans|regulatory|standard", re.I), "compliance"),
    (re.compile(r"risk\s+trend|getting\s+(better|worse)|improv|over\s+time", re.I), "trend"),
    (re.compile(r"attack\s+chain|attack\s+path|kill\s+chain|exploit\s+chain", re.I), "attack_chains"),
    (re.compile(r"summary|overview|posture|executive|status|how\s+(are|am)\s+(we|i)\s+doing", re.I), "summary"),
    (re.compile(r"mttr|mean\s+time|time\s+to\s+(fix|remediat|resolv)", re.I), "mttr"),
    (re.compile(r"scanner|tool|sast|dast|sca|source", re.I), "scanners"),
    (re.compile(r"(false\s+positive|fp|noise)", re.I), "false_positives"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_value(sev) -> str:
    return sev.value if hasattr(sev, "value") else str(sev)


def _risk_level_from_counts(critical: int, high: int, total: int) -> str:
    if critical > 0:
        return "critical"
    if high > 0:
        return "high"
    if total > 0:
        return "medium"
    return "low"


async def _get_findings(db: AsyncSession, product_id: int) -> list[Finding]:
    result = await db.execute(
        select(Finding)
        .where(Finding.product_id == product_id)
        .where(Finding.status.notin_([FindingStatus.FALSE_POSITIVE, FindingStatus.OUT_OF_SCOPE, FindingStatus.DUPLICATE]))
    )
    return list(result.scalars().all())


async def _get_product(db: AsyncSession, product_id: int) -> Optional[Product]:
    result = await db.execute(select(Product).where(Product.id == product_id))
    return result.scalar_one_or_none()


async def _severity_counts(db: AsyncSession, product_id: int) -> dict[str, int]:
    result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.product_id == product_id)
        .where(Finding.status.notin_([FindingStatus.FALSE_POSITIVE, FindingStatus.OUT_OF_SCOPE, FindingStatus.DUPLICATE]))
        .group_by(Finding.severity)
    )
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for sev, cnt in result.all():
        counts[_severity_value(sev)] = cnt
    return counts


# ---------------------------------------------------------------------------
# Core analysis functions
# ---------------------------------------------------------------------------

async def analyze_product_posture(db: AsyncSession, product_id: int) -> dict:
    """Deep analysis of the security posture for a product."""
    product = await _get_product(db, product_id)
    if not product:
        return {"error": "Product not found"}

    findings = await _get_findings(db, product_id)
    sev_counts = await _severity_counts(db, product_id)
    total = len(findings)
    critical_count = sev_counts.get("critical", 0)
    high_count = sev_counts.get("high", 0)

    # Active / open rate
    active_findings = [f for f in findings if _severity_value(f.status) in ("active", "verified")]
    open_rate = round((len(active_findings) / total * 100) if total else 0, 1)

    # Average age
    now = datetime.now(timezone.utc)
    ages = []
    for f in findings:
        df = f.date_found
        if df:
            if df.tzinfo is None:
                df = df.replace(tzinfo=timezone.utc)
            ages.append((now - df).days)
    avg_age = round(sum(ages) / len(ages), 1) if ages else 0

    # Mean time to remediate
    mitigated = [f for f in findings if f.date_mitigated and f.date_found]
    mttr_values = []
    for f in mitigated:
        df, dm = f.date_found, f.date_mitigated
        if df.tzinfo is None:
            df = df.replace(tzinfo=timezone.utc)
        if dm.tzinfo is None:
            dm = dm.replace(tzinfo=timezone.utc)
        mttr_values.append((dm - df).days)
    mttr_days = round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else 0

    # Top risks: group by title similarity, pick top items
    top_risks = _compute_top_risks(findings)

    # Attack chains
    attack_chains = _detect_attack_chains(findings)

    # Recommended actions
    recommended_actions = _build_recommendations(findings, sev_counts, attack_chains, avg_age, mttr_days)

    risk_level = _risk_level_from_counts(critical_count, high_count, total)

    # Executive summary
    executive_summary = _build_executive_summary(product, total, sev_counts, risk_level, avg_age, mttr_days)

    return {
        "product_id": product_id,
        "product_name": product.name,
        "executive_summary": executive_summary,
        "risk_level": risk_level,
        "top_risks": top_risks[:10],
        "attack_chains": attack_chains,
        "recommended_actions": recommended_actions,
        "metrics": {
            "total_findings": total,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": sev_counts.get("medium", 0),
            "low_count": sev_counts.get("low", 0),
            "info_count": sev_counts.get("info", 0),
            "open_rate": open_rate,
            "avg_age_days": avg_age,
            "mttr_days": mttr_days,
        },
    }


async def generate_executive_report(db: AsyncSession, product_id: int) -> dict:
    """Generate a structured executive report with multiple sections."""
    product = await _get_product(db, product_id)
    if not product:
        return {"error": "Product not found"}

    findings = await _get_findings(db, product_id)
    sev_counts = await _severity_counts(db, product_id)
    total = len(findings)
    critical_count = sev_counts.get("critical", 0)
    high_count = sev_counts.get("high", 0)
    risk_level = _risk_level_from_counts(critical_count, high_count, total)

    now = datetime.now(timezone.utc)

    # --- Overview ---
    overview = {
        "product_name": product.name,
        "product_type": product.product_type.value if hasattr(product.product_type, "value") else str(product.product_type),
        "business_criticality": product.business_criticality or "medium",
        "total_findings": total,
        "risk_level": risk_level,
        "report_date": now.isoformat(),
    }

    # --- Risk summary ---
    risk_summary = {
        "severity_distribution": sev_counts,
        "risk_level": risk_level,
        "risk_score": product.risk_score or 0.0,
    }

    # --- Top vulnerabilities ---
    top_vulns = []
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(_severity_value(f.severity)) if _severity_value(f.severity) in SEVERITY_ORDER else 5),
    )
    for f in sorted_findings[:15]:
        top_vulns.append({
            "id": f.id,
            "title": f.title,
            "severity": _severity_value(f.severity),
            "cvss_score": f.cvss_score,
            "cve": f.cve,
            "cwe": f.cwe,
            "component": f.component,
            "file_path": f.file_path,
            "status": _severity_value(f.status),
            "age_days": (now - f.date_found.replace(tzinfo=timezone.utc)).days if f.date_found else None,
        })

    # --- Trend analysis ---
    # Group findings by month of discovery
    monthly: dict[str, dict[str, int]] = defaultdict(lambda: {s: 0 for s in SEVERITY_ORDER})
    for f in findings:
        if f.date_found:
            month_key = f.date_found.strftime("%Y-%m")
            monthly[month_key][_severity_value(f.severity)] += 1
    trend_analysis = [
        {"month": k, "counts": v} for k, v in sorted(monthly.items())
    ]

    # --- Compliance gaps ---
    finding_cwes = {f.cwe for f in findings if f.cwe}
    compliance_gaps = {}
    for framework, categories in COMPLIANCE_FRAMEWORKS.items():
        gaps = {}
        for category, cwes in categories.items():
            matched = finding_cwes & set(cwes)
            if matched:
                count = sum(1 for f in findings if f.cwe in matched)
                gaps[category] = {"matched_cwes": sorted(matched), "finding_count": count}
        if gaps:
            compliance_gaps[framework] = gaps

    # --- Recommendations ---
    attack_chains = _detect_attack_chains(findings)
    recommendations = _build_recommendations(findings, sev_counts, attack_chains, 0, 0)

    # --- Next steps ---
    next_steps = []
    if critical_count > 0:
        next_steps.append(f"Immediately remediate {critical_count} critical findings to reduce attack surface.")
    if high_count > 0:
        next_steps.append(f"Plan sprint work to address {high_count} high-severity findings.")
    if attack_chains:
        next_steps.append(f"Break {len(attack_chains)} identified attack chains by addressing their weakest links.")
    if compliance_gaps:
        next_steps.append("Review compliance gaps and map remediation to framework requirements.")
    if not next_steps:
        next_steps.append("Continue monitoring. Security posture is in good shape.")

    return {
        "product_id": product_id,
        "overview": overview,
        "risk_summary": risk_summary,
        "top_vulnerabilities": top_vulns,
        "trend_analysis": trend_analysis,
        "compliance_gaps": compliance_gaps,
        "recommendations": recommendations,
        "next_steps": next_steps,
    }


async def answer_security_question(
    db: AsyncSession,
    question: str,
    product_id: Optional[int] = None,
) -> dict:
    """Handle natural-language questions about security posture."""

    # Determine intent
    intent = "general"
    for pattern, intent_name in QUESTION_PATTERNS:
        if pattern.search(question):
            intent = intent_name
            break

    # Build base filter
    base_filter = []
    base_filter.append(
        Finding.status.notin_([FindingStatus.FALSE_POSITIVE, FindingStatus.OUT_OF_SCOPE, FindingStatus.DUPLICATE])
    )
    if product_id:
        base_filter.append(Finding.product_id == product_id)

    # Route by intent
    if intent == "counts":
        return await _answer_counts(db, question, base_filter, product_id)
    elif intent == "top_risks":
        return await _answer_top_risks(db, base_filter, product_id)
    elif intent == "fix_first":
        return await _answer_fix_first(db, base_filter, product_id)
    elif intent == "compliance":
        return await _answer_compliance(db, base_filter, product_id)
    elif intent == "trend":
        return await _answer_trend(db, base_filter, product_id)
    elif intent == "attack_chains":
        return await _answer_attack_chains(db, product_id)
    elif intent == "summary":
        return await _answer_summary(db, base_filter, product_id)
    elif intent == "mttr":
        return await _answer_mttr(db, base_filter, product_id)
    elif intent == "scanners":
        return await _answer_scanners(db, base_filter, product_id)
    elif intent == "false_positives":
        return await _answer_false_positives(db, product_id)
    else:
        return await _answer_general(db, base_filter, product_id)


async def identify_attack_chains(db: AsyncSession, product_id: int) -> list[dict]:
    """Analyze findings to identify potential multi-step attack chains."""
    findings = await _get_findings(db, product_id)
    return _detect_attack_chains(findings)


# ---------------------------------------------------------------------------
# Chat intent handlers
# ---------------------------------------------------------------------------

async def _answer_counts(db: AsyncSession, question: str, filters: list, product_id: Optional[int]) -> dict:
    sev_match = re.search(r"(critical|high|medium|low|info)", question, re.I)
    target_sev = sev_match.group(1).lower() if sev_match else None

    result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(*filters)
        .group_by(Finding.severity)
    )
    counts = {}
    total = 0
    for sev, cnt in result.all():
        key = _severity_value(sev)
        counts[key] = cnt
        total += cnt

    if target_sev and target_sev in counts:
        response = f"There are {counts[target_sev]} {target_sev}-severity findings."
    else:
        parts = [f"{counts.get(s, 0)} {s}" for s in SEVERITY_ORDER if counts.get(s, 0) > 0]
        response = f"Total findings: {total}. Breakdown: {', '.join(parts)}."

    return {
        "response": response,
        "data": {"severity_counts": counts, "total": total},
        "suggestions": ["What should I fix first?", "Show me attack chains", "How is our compliance?"],
    }


async def _answer_top_risks(db: AsyncSession, filters: list, product_id: Optional[int]) -> dict:
    result = await db.execute(
        select(Finding)
        .where(*filters)
        .order_by(
            case(
                (Finding.severity == FindingSeverity.CRITICAL, 0),
                (Finding.severity == FindingSeverity.HIGH, 1),
                (Finding.severity == FindingSeverity.MEDIUM, 2),
                (Finding.severity == FindingSeverity.LOW, 3),
                else_=4,
            ),
            Finding.cvss_score.desc().nullslast(),
        )
        .limit(10)
    )
    findings = list(result.scalars().all())
    risks = [
        {
            "id": f.id,
            "title": f.title,
            "severity": _severity_value(f.severity),
            "cvss_score": f.cvss_score,
            "cve": f.cve,
            "component": f.component,
        }
        for f in findings
    ]

    if risks:
        top = risks[0]
        response = f"Your top risk is \"{top['title']}\" ({top['severity']} severity"
        if top["cvss_score"]:
            response += f", CVSS {top['cvss_score']}"
        response += f"). You have {len(risks)} high-priority findings that need attention."
    else:
        response = "No active findings found. Your security posture looks clean."

    return {
        "response": response,
        "data": {"top_risks": risks},
        "suggestions": ["What should I fix first?", "Show me attack chains", "Give me an executive summary"],
    }


async def _answer_fix_first(db: AsyncSession, filters: list, product_id: Optional[int]) -> dict:
    result = await db.execute(
        select(Finding)
        .where(*filters)
        .where(Finding.severity.in_([FindingSeverity.CRITICAL, FindingSeverity.HIGH]))
        .order_by(
            case(
                (Finding.severity == FindingSeverity.CRITICAL, 0),
                (Finding.severity == FindingSeverity.HIGH, 1),
                else_=2,
            ),
            Finding.cvss_score.desc().nullslast(),
            Finding.date_found.asc(),
        )
        .limit(10)
    )
    findings = list(result.scalars().all())
    actions = []
    for i, f in enumerate(findings, 1):
        actions.append({
            "priority": i,
            "finding_id": f.id,
            "title": f.title,
            "severity": _severity_value(f.severity),
            "cvss_score": f.cvss_score,
            "reason": f"{'Critical' if _severity_value(f.severity) == 'critical' else 'High'} severity"
                      + (f", CVSS {f.cvss_score}" if f.cvss_score else "")
                      + (f", CVE: {f.cve}" if f.cve else ""),
        })

    if actions:
        response = (
            f"I recommend fixing these {len(actions)} findings first, ordered by priority. "
            f"Start with \"{actions[0]['title']}\" — it is the highest risk item."
        )
    else:
        response = "No critical or high severity findings to remediate. Consider reviewing medium-severity items."

    return {
        "response": response,
        "data": {"prioritized_actions": actions},
        "suggestions": ["Show me top risks", "What about compliance?", "Show attack chains"],
    }


async def _answer_compliance(db: AsyncSession, filters: list, product_id: Optional[int]) -> dict:
    result = await db.execute(select(Finding).where(*filters))
    findings = list(result.scalars().all())
    finding_cwes = {f.cwe for f in findings if f.cwe}

    gaps = {}
    for framework, categories in COMPLIANCE_FRAMEWORKS.items():
        framework_gaps = {}
        for category, cwes in categories.items():
            matched = finding_cwes & set(cwes)
            if matched:
                count = sum(1 for f in findings if f.cwe in matched)
                framework_gaps[category] = {"matched_cwes": sorted(matched), "finding_count": count}
        if framework_gaps:
            gaps[framework] = framework_gaps

    if gaps:
        total_categories = sum(len(v) for v in gaps.values())
        response = f"Compliance analysis found gaps in {total_categories} categories across {len(gaps)} frameworks."
    else:
        response = "No compliance gaps detected based on CWE mappings. Your findings do not map to known framework categories."

    return {
        "response": response,
        "data": {"compliance_gaps": gaps},
        "suggestions": ["What should I fix first?", "Show me top risks", "Give me an executive summary"],
    }


async def _answer_trend(db: AsyncSession, filters: list, product_id: Optional[int]) -> dict:
    result = await db.execute(select(Finding).where(*filters))
    findings = list(result.scalars().all())

    monthly: dict[str, int] = defaultdict(int)
    for f in findings:
        if f.date_found:
            monthly[f.date_found.strftime("%Y-%m")] += 1

    sorted_months = sorted(monthly.items())
    if len(sorted_months) >= 2:
        recent = sorted_months[-1][1]
        previous = sorted_months[-2][1]
        if recent > previous:
            direction = "increasing"
        elif recent < previous:
            direction = "decreasing"
        else:
            direction = "stable"
        response = (
            f"Finding trend is {direction}. "
            f"Last month: {recent} findings, previous month: {previous} findings."
        )
    elif sorted_months:
        response = f"Only one month of data available ({sorted_months[0][0]}): {sorted_months[0][1]} findings."
    else:
        response = "No trend data available — no findings with discovery dates."

    return {
        "response": response,
        "data": {"monthly_trend": [{"month": m, "count": c} for m, c in sorted_months]},
        "suggestions": ["What are my top risks?", "Show me an executive summary", "How is compliance?"],
    }


async def _answer_attack_chains(db: AsyncSession, product_id: Optional[int]) -> dict:
    if not product_id:
        return {
            "response": "Please specify a product to analyze attack chains.",
            "data": None,
            "suggestions": ["Analyze product 1", "Show me top risks"],
        }
    chains = await identify_attack_chains(db, product_id)
    if chains:
        response = (
            f"I identified {len(chains)} potential attack chains. "
            f"The most dangerous is \"{chains[0]['name']}\" with a risk score of {chains[0]['risk_score']}."
        )
    else:
        response = "No multi-step attack chains detected based on current findings."

    return {
        "response": response,
        "data": {"attack_chains": chains},
        "suggestions": ["What should I fix first?", "Show me compliance gaps", "Give me executive summary"],
    }


async def _answer_summary(db: AsyncSession, filters: list, product_id: Optional[int]) -> dict:
    if product_id:
        posture = await analyze_product_posture(db, product_id)
        return {
            "response": posture.get("executive_summary", "Analysis complete."),
            "data": posture.get("metrics"),
            "suggestions": ["What should I fix first?", "Show me attack chains", "How is compliance?"],
        }

    result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(*filters)
        .group_by(Finding.severity)
    )
    counts = {}
    total = 0
    for sev, cnt in result.all():
        counts[_severity_value(sev)] = cnt
        total += cnt

    response = (
        f"Across all products: {total} active findings. "
        f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low."
    )
    return {
        "response": response,
        "data": {"total": total, "severity_counts": counts},
        "suggestions": ["What are the top risks?", "What should I fix first?", "Show compliance status"],
    }


async def _answer_mttr(db: AsyncSession, filters: list, product_id: Optional[int]) -> dict:
    result = await db.execute(
        select(Finding)
        .where(*filters)
        .where(Finding.date_mitigated.isnot(None))
    )
    mitigated = list(result.scalars().all())

    now = datetime.now(timezone.utc)
    durations = []
    for f in mitigated:
        if f.date_found and f.date_mitigated:
            df = f.date_found.replace(tzinfo=timezone.utc) if f.date_found.tzinfo is None else f.date_found
            dm = f.date_mitigated.replace(tzinfo=timezone.utc) if f.date_mitigated.tzinfo is None else f.date_mitigated
            durations.append((dm - df).days)

    if durations:
        avg = round(sum(durations) / len(durations), 1)
        fastest = min(durations)
        slowest = max(durations)
        response = (
            f"Mean Time to Remediate (MTTR): {avg} days across {len(durations)} resolved findings. "
            f"Fastest: {fastest} days, slowest: {slowest} days."
        )
        data = {"mttr_days": avg, "resolved_count": len(durations), "fastest_days": fastest, "slowest_days": slowest}
    else:
        response = "No resolved findings with remediation dates available to calculate MTTR."
        data = {"mttr_days": 0, "resolved_count": 0}

    return {
        "response": response,
        "data": data,
        "suggestions": ["What are my top risks?", "What should I fix first?", "Show trend"],
    }


async def _answer_scanners(db: AsyncSession, filters: list, product_id: Optional[int]) -> dict:
    result = await db.execute(
        select(Finding.scanner, Finding.tool_type, func.count(Finding.id))
        .where(*filters)
        .group_by(Finding.scanner, Finding.tool_type)
    )
    scanner_data = []
    for scanner, tool_type, count in result.all():
        scanner_data.append({
            "scanner": scanner or "Unknown",
            "tool_type": tool_type or "Unknown",
            "finding_count": count,
        })

    if scanner_data:
        total_scanners = len(scanner_data)
        top = max(scanner_data, key=lambda x: x["finding_count"])
        response = (
            f"{total_scanners} scanner(s) contributed findings. "
            f"Top contributor: {top['scanner']} ({top['tool_type']}) with {top['finding_count']} findings."
        )
    else:
        response = "No scanner data available for the current findings."

    return {
        "response": response,
        "data": {"scanners": scanner_data},
        "suggestions": ["What are the top risks?", "Show me compliance status", "What should I fix first?"],
    }


async def _answer_false_positives(db: AsyncSession, product_id: Optional[int]) -> dict:
    filters = [Finding.status == FindingStatus.FALSE_POSITIVE]
    if product_id:
        filters.append(Finding.product_id == product_id)

    result = await db.execute(
        select(func.count(Finding.id)).where(*filters)
    )
    fp_count = result.scalar() or 0

    # Total for ratio
    total_filters = []
    if product_id:
        total_filters.append(Finding.product_id == product_id)
    total_result = await db.execute(
        select(func.count(Finding.id)).where(*total_filters) if total_filters else select(func.count(Finding.id))
    )
    total = total_result.scalar() or 0

    rate = round((fp_count / total * 100), 1) if total else 0

    response = (
        f"{fp_count} findings marked as false positive out of {total} total ({rate}% FP rate)."
    )
    return {
        "response": response,
        "data": {"false_positive_count": fp_count, "total_findings": total, "fp_rate": rate},
        "suggestions": ["What are the top risks?", "What should I fix first?", "Show me compliance"],
    }


async def _answer_general(db: AsyncSession, filters: list, product_id: Optional[int]) -> dict:
    """Fallback: provide a helpful summary with guidance."""
    result = await db.execute(
        select(func.count(Finding.id)).where(*filters)
    )
    total = result.scalar() or 0

    response = (
        f"I found {total} active findings. "
        "You can ask me about top risks, compliance status, attack chains, "
        "what to fix first, MTTR, scanner breakdown, or request an executive summary."
    )
    return {
        "response": response,
        "data": {"total_findings": total},
        "suggestions": [
            "What are my top risks?",
            "What should I fix first?",
            "Show me compliance status",
            "Are there any attack chains?",
            "Give me an executive summary",
        ],
    }


# ---------------------------------------------------------------------------
# Internal analysis helpers
# ---------------------------------------------------------------------------

def _compute_top_risks(findings: list[Finding]) -> list[dict]:
    """Group findings by CWE or title pattern and rank by severity/count."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.cwe:
            key = f"CWE-{f.cwe}"
        else:
            # Normalize title for grouping
            key = re.sub(r"[^a-zA-Z\s]", "", f.title or "Unknown").strip()[:60]
        groups[key].append(f)

    risks = []
    for key, group in groups.items():
        severities = [_severity_value(f.severity) for f in group]
        worst = min(severities, key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 5)
        risks.append({
            "title": key,
            "description": group[0].description[:200] if group[0].description else f"Group of {len(group)} related findings.",
            "severity": worst,
            "affected_count": len(group),
        })

    risks.sort(key=lambda r: (SEVERITY_ORDER.index(r["severity"]) if r["severity"] in SEVERITY_ORDER else 5, -r["affected_count"]))
    return risks


def _detect_attack_chains(findings: list[Finding]) -> list[dict]:
    """Match findings against known attack chain templates."""
    finding_cwes = {f.cwe for f in findings if f.cwe}
    finding_titles = [f.title or "" for f in findings]

    chains = []
    for template in ATTACK_CHAIN_TEMPLATES:
        # Check CWE-based match
        cwe_match = True
        for cwe_set in template["required_cwes"]:
            if not (finding_cwes & cwe_set):
                cwe_match = False
                break

        # Check title-based match as fallback
        title_match = True
        for pattern_group in template["required_titles"]:
            group_matched = False
            for pattern in pattern_group:
                for title in finding_titles:
                    if pattern.search(title):
                        group_matched = True
                        break
                if group_matched:
                    break
            if not group_matched:
                title_match = False
                break

        if cwe_match or title_match:
            # Gather the actual findings involved
            involved = []
            for f in findings:
                for cwe_set in template["required_cwes"]:
                    if f.cwe and f.cwe in cwe_set:
                        involved.append({"id": f.id, "title": f.title, "severity": _severity_value(f.severity)})
                        break
                else:
                    for pattern_group in template["required_titles"]:
                        matched = False
                        for pattern in pattern_group:
                            if pattern.search(f.title or ""):
                                involved.append({"id": f.id, "title": f.title, "severity": _severity_value(f.severity)})
                                matched = True
                                break
                        if matched:
                            break

            # Deduplicate by finding id
            seen_ids = set()
            unique_involved = []
            for item in involved:
                if item["id"] not in seen_ids:
                    seen_ids.add(item["id"])
                    unique_involved.append(item)

            # Calculate risk score based on severities of involved findings
            severity_scores = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 1}
            involved_score = sum(
                severity_scores.get(i["severity"], 1) for i in unique_involved
            )
            risk_score = min(10.0, round(template["base_risk"] * (1 + involved_score / 50), 1))

            chains.append({
                "name": template["name"],
                "description": template["description"],
                "steps": unique_involved,
                "risk_score": risk_score,
                "finding_count": len(unique_involved),
            })

    chains.sort(key=lambda c: c["risk_score"], reverse=True)
    return chains


def _build_recommendations(
    findings: list[Finding],
    sev_counts: dict[str, int],
    attack_chains: list[dict],
    avg_age: float,
    mttr_days: float,
) -> list[dict]:
    """Build a prioritized list of recommended actions."""
    actions = []
    priority = 1

    critical = sev_counts.get("critical", 0)
    high = sev_counts.get("high", 0)

    if critical > 0:
        actions.append({
            "priority": priority,
            "action": f"Remediate {critical} critical-severity findings immediately.",
            "effort": "high" if critical > 5 else "medium",
            "impact": "critical",
            "rationale": "Critical findings represent the highest risk to your application and should be addressed within 24-48 hours.",
        })
        priority += 1

    if attack_chains:
        actions.append({
            "priority": priority,
            "action": f"Break {len(attack_chains)} attack chain(s) by addressing key findings in each chain.",
            "effort": "medium",
            "impact": "high",
            "rationale": "Attack chains combine multiple vulnerabilities into more dangerous exploit paths.",
        })
        priority += 1

    if high > 0:
        actions.append({
            "priority": priority,
            "action": f"Schedule remediation of {high} high-severity findings in the next sprint.",
            "effort": "high" if high > 10 else "medium",
            "impact": "high",
            "rationale": "High-severity findings should be addressed within 1-2 weeks to maintain acceptable risk levels.",
        })
        priority += 1

    if avg_age > 90:
        actions.append({
            "priority": priority,
            "action": "Address aging vulnerabilities — average finding age exceeds 90 days.",
            "effort": "medium",
            "impact": "medium",
            "rationale": f"Findings average {avg_age} days old. Long-lived vulnerabilities increase exploit probability.",
        })
        priority += 1

    if mttr_days > 30:
        actions.append({
            "priority": priority,
            "action": "Improve remediation velocity — MTTR exceeds 30 days.",
            "effort": "low",
            "impact": "medium",
            "rationale": f"Current MTTR is {mttr_days} days. Industry best practice targets under 30 days for high severity.",
        })
        priority += 1

    # Check for scanner diversity
    scanners = {f.scanner for f in findings if f.scanner}
    tool_types = {f.tool_type for f in findings if f.tool_type}
    if len(tool_types) < 3:
        actions.append({
            "priority": priority,
            "action": "Expand security tooling — fewer than 3 tool types in use.",
            "effort": "medium",
            "impact": "medium",
            "rationale": "A comprehensive AppSec program should include SAST, DAST, SCA, and secrets scanning.",
        })
        priority += 1

    if not actions:
        actions.append({
            "priority": 1,
            "action": "Continue monitoring and maintain current security practices.",
            "effort": "low",
            "impact": "low",
            "rationale": "No immediate action items identified. Security posture is acceptable.",
        })

    return actions


def _build_executive_summary(
    product: Product,
    total: int,
    sev_counts: dict[str, int],
    risk_level: str,
    avg_age: float,
    mttr_days: float,
) -> str:
    """Build a 3-4 sentence executive summary."""
    critical = sev_counts.get("critical", 0)
    high = sev_counts.get("high", 0)

    sentences = []
    sentences.append(
        f"{product.name} has {total} active security findings with an overall risk level of {risk_level}."
    )

    if critical > 0 or high > 0:
        sentences.append(
            f"There are {critical} critical and {high} high-severity vulnerabilities requiring immediate attention."
        )
    else:
        sentences.append(
            "No critical or high severity vulnerabilities are currently present."
        )

    if avg_age > 0:
        sentences.append(
            f"The average finding age is {avg_age} days"
            + (f" with a mean time to remediate of {mttr_days} days." if mttr_days > 0 else ".")
        )

    if total == 0:
        sentences.append("The security posture is currently clean with no outstanding findings.")
    elif risk_level in ("critical", "high"):
        sentences.append("Immediate action is recommended to reduce the attack surface.")
    else:
        sentences.append("The security posture is manageable but continued monitoring is advised.")

    return " ".join(sentences)
