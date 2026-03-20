import logging
from collections import defaultdict
from typing import Any, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus, Endpoint
from app.models.product import Product

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE categories relevant to API security
# ---------------------------------------------------------------------------

API_CWE_CATEGORIES: dict[str, set[int]] = {
    "broken_authentication": {287, 306, 307, 798, 259, 384},
    "broken_authorization": {639, 284, 269, 285},
    "injection": {89, 78, 77, 94, 917},
    "data_exposure": {200, 311, 312, 319, 532},
    "rate_limiting": {770, 799, 400},
    "ssrf": {918},
    "mass_assignment": {915},
    "security_misconfiguration": {16, 1032, 614, 693},
}

# Reverse map: CWE -> category
CWE_TO_CATEGORY: dict[int, str] = {}
for _cat, _cwes in API_CWE_CATEGORIES.items():
    for _cwe in _cwes:
        CWE_TO_CATEGORY[_cwe] = _cat


class ApiSecurityService:
    """API security posture analysis engine."""

    # ------------------------------------------------------------------
    # Posture analysis
    # ------------------------------------------------------------------

    async def analyze_api_posture(
        self, db: AsyncSession, product_id: int
    ) -> dict[str, Any]:
        """Analyse the API security posture for a product.

        Returns metrics including endpoint counts, auth coverage,
        rate-limiting status, data exposure risks, and findings by category.
        """
        # Get endpoints
        ep_result = await db.execute(
            select(Endpoint).where(Endpoint.product_id == product_id)
        )
        endpoints = list(ep_result.scalars().all())
        total_endpoints = len(endpoints)

        # Get open findings
        findings = await self._get_api_findings(db, product_id)

        # Categorise findings by API security category
        findings_by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in findings:
            category = CWE_TO_CATEGORY.get(f.cwe, "other") if f.cwe else "other"
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            findings_by_category[category].append({
                "finding_id": f.id,
                "title": f.title or "Untitled",
                "severity": sev,
                "cwe": f.cwe,
            })

        # Auth coverage estimate based on auth-related findings
        auth_findings = len(findings_by_category.get("broken_authentication", []))
        auth_coverage = max(0.0, 100.0 - (auth_findings * 15.0))
        auth_coverage = min(100.0, auth_coverage)

        # Rate limiting status
        rate_limit_findings = len(findings_by_category.get("rate_limiting", []))
        if rate_limit_findings == 0:
            rate_limiting_status = "configured"
        elif rate_limit_findings <= 2:
            rate_limiting_status = "partial"
        else:
            rate_limiting_status = "missing"

        # Data exposure risks
        data_exposure_risks = findings_by_category.get("data_exposure", [])

        # Deprecated endpoints (heuristic: endpoints with no recent findings
        # or marked with common deprecation patterns)
        deprecated_endpoints: list[dict[str, Any]] = []
        for ep in endpoints:
            path = ep.path or ""
            if any(marker in path.lower() for marker in ["/v1/", "/v0/", "/legacy/", "/deprecated/"]):
                deprecated_endpoints.append({
                    "id": ep.id,
                    "path": path,
                    "host": ep.host,
                })

        # Category summary counts
        category_counts = {
            cat: len(items)
            for cat, items in findings_by_category.items()
        }

        return {
            "product_id": product_id,
            "total_endpoints": total_endpoints,
            "auth_coverage": round(auth_coverage, 1),
            "rate_limiting_status": rate_limiting_status,
            "data_exposure_risks": data_exposure_risks,
            "deprecated_endpoints": deprecated_endpoints,
            "api_findings_by_category": dict(findings_by_category),
            "category_counts": category_counts,
            "total_api_findings": len(findings),
        }

    # ------------------------------------------------------------------
    # OpenAPI / Swagger parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_openapi_spec(spec_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse an OpenAPI/Swagger JSON spec and extract endpoint information.

        Returns a list of endpoint dicts with method, path, auth requirements,
        parameters, and response types.
        """
        endpoints: list[dict[str, Any]] = []
        paths = spec_data.get("paths", {})

        # Determine spec version
        is_swagger_2 = spec_data.get("swagger", "").startswith("2")
        global_security = spec_data.get("security", [])

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.startswith("x-") or method == "parameters":
                    continue
                if not isinstance(operation, dict):
                    continue

                # Auth requirements
                op_security = operation.get("security", global_security)
                requires_auth = bool(op_security and any(s for s in op_security))

                # Parameters
                params = operation.get("parameters", [])
                param_list = []
                for p in params:
                    if isinstance(p, dict):
                        param_list.append({
                            "name": p.get("name", ""),
                            "in": p.get("in", ""),
                            "required": p.get("required", False),
                            "type": p.get("type") or p.get("schema", {}).get("type", ""),
                        })

                # Request body (OpenAPI 3.x)
                request_body = operation.get("requestBody", {})
                if request_body:
                    content = request_body.get("content", {})
                    for content_type in content:
                        param_list.append({
                            "name": "body",
                            "in": "body",
                            "required": request_body.get("required", False),
                            "type": content_type,
                        })

                # Response types
                responses = operation.get("responses", {})
                response_types = list(responses.keys())

                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "summary": operation.get("summary", ""),
                    "operation_id": operation.get("operationId", ""),
                    "requires_auth": requires_auth,
                    "parameters": param_list,
                    "response_types": response_types,
                    "tags": operation.get("tags", []),
                    "deprecated": operation.get("deprecated", False),
                })

        return endpoints

    # ------------------------------------------------------------------
    # Correlate findings with API endpoints
    # ------------------------------------------------------------------

    async def correlate_api_findings(
        self, db: AsyncSession, product_id: int, endpoints: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Match DAST findings to API endpoints by path correlation.

        Returns the endpoints list enriched with correlated findings.
        """
        findings = await self._get_api_findings(db, product_id)

        # Build a map of finding endpoints from the Endpoint model
        finding_eps_result = await db.execute(
            select(Endpoint).where(Endpoint.product_id == product_id)
        )
        finding_endpoints = list(finding_eps_result.scalars().all())

        # Map finding_id -> endpoint paths from the findings' endpoints
        finding_id_to_paths: dict[int, set[str]] = defaultdict(set)
        for ep in finding_endpoints:
            if ep.path:
                finding_id_to_paths[ep.finding_id].add(ep.path.lower())

        enriched: list[dict[str, Any]] = []
        for ep in endpoints:
            ep_path = ep.get("path", "").lower()
            matched_findings: list[dict[str, Any]] = []

            for f in findings:
                # Match by finding endpoint paths
                f_paths = finding_id_to_paths.get(f.id, set())
                path_match = any(
                    ep_path in fp or fp in ep_path
                    for fp in f_paths
                )
                # Also match by file_path or title containing the endpoint path
                title_match = ep_path in (f.title or "").lower()

                if path_match or title_match:
                    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    matched_findings.append({
                        "finding_id": f.id,
                        "title": f.title,
                        "severity": sev,
                        "cwe": f.cwe,
                    })

            enriched.append({
                **ep,
                "correlated_findings": matched_findings,
                "risk_level": _endpoint_risk_level(matched_findings, ep.get("requires_auth", True)),
            })

        return enriched

    # ------------------------------------------------------------------
    # API risk score
    # ------------------------------------------------------------------

    async def get_api_risk_score(
        self, db: AsyncSession, product_id: int
    ) -> dict[str, Any]:
        """Calculate an API-specific risk score for a product (0-100).

        Factors:
            - Number and severity of API-related findings
            - Auth coverage gaps
            - Rate limiting status
            - Data exposure issues
        """
        posture = await self.analyze_api_posture(db, product_id)

        score = 100.0

        # Penalty for API findings by severity
        severity_penalty = {"critical": 15.0, "high": 10.0, "medium": 5.0, "low": 1.5, "info": 0.0}
        for _cat, cat_findings in posture["api_findings_by_category"].items():
            for f in cat_findings:
                score -= severity_penalty.get(f["severity"], 2.0)

        # Penalty for auth coverage gaps
        auth_gap = 100.0 - posture["auth_coverage"]
        score -= auth_gap * 0.3

        # Penalty for rate limiting issues
        if posture["rate_limiting_status"] == "missing":
            score -= 15.0
        elif posture["rate_limiting_status"] == "partial":
            score -= 7.0

        # Penalty for deprecated endpoints still active
        score -= len(posture["deprecated_endpoints"]) * 3.0

        score = max(0.0, min(100.0, round(score, 1)))

        if score >= 80:
            rating = "good"
        elif score >= 60:
            rating = "moderate"
        elif score >= 40:
            rating = "poor"
        else:
            rating = "critical"

        return {
            "product_id": product_id,
            "api_risk_score": score,
            "rating": rating,
            "factors": {
                "auth_coverage": posture["auth_coverage"],
                "rate_limiting_status": posture["rate_limiting_status"],
                "total_api_findings": posture["total_api_findings"],
                "deprecated_endpoints": len(posture["deprecated_endpoints"]),
                "data_exposure_risks": len(posture["data_exposure_risks"]),
            },
        }

    # ------------------------------------------------------------------
    # Org-wide API overview
    # ------------------------------------------------------------------

    async def get_api_overview(
        self, db: AsyncSession
    ) -> dict[str, Any]:
        """Org-wide API security statistics across all products."""
        products_result = await db.execute(select(Product).order_by(Product.name))
        products = products_result.scalars().all()

        total_endpoints = 0
        total_api_findings = 0
        products_with_issues: list[dict[str, Any]] = []
        auth_coverage_values: list[float] = []

        for product in products:
            posture = await self.analyze_api_posture(db, product.id)
            risk = await self.get_api_risk_score(db, product.id)

            total_endpoints += posture["total_endpoints"]
            total_api_findings += posture["total_api_findings"]
            auth_coverage_values.append(posture["auth_coverage"])

            if posture["total_api_findings"] > 0:
                products_with_issues.append({
                    "product_id": product.id,
                    "product_name": product.name,
                    "api_risk_score": risk["api_risk_score"],
                    "rating": risk["rating"],
                    "total_endpoints": posture["total_endpoints"],
                    "total_api_findings": posture["total_api_findings"],
                    "auth_coverage": posture["auth_coverage"],
                })

        products_with_issues.sort(key=lambda p: p["api_risk_score"])

        avg_auth_coverage = (
            round(sum(auth_coverage_values) / len(auth_coverage_values), 1)
            if auth_coverage_values
            else 100.0
        )

        return {
            "total_products": len(products),
            "total_endpoints": total_endpoints,
            "total_api_findings": total_api_findings,
            "average_auth_coverage": avg_auth_coverage,
            "products_with_issues": products_with_issues,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _get_api_findings(
        db: AsyncSession, product_id: int
    ) -> list[Finding]:
        """Fetch open findings relevant to API security for a product.

        Includes DAST findings and any finding with an API-related CWE.
        """
        all_api_cwes: set[int] = set()
        for cwes in API_CWE_CATEGORIES.values():
            all_api_cwes.update(cwes)

        # Fetch findings that are DAST or have API-related CWEs
        query = (
            select(Finding)
            .where(
                Finding.product_id == product_id,
                Finding.is_duplicate == False,  # noqa: E712
                Finding.status.in_([FindingStatus.ACTIVE, FindingStatus.VERIFIED]),
            )
            .order_by(Finding.severity, Finding.id)
        )
        result = await db.execute(query)
        all_findings = list(result.scalars().all())

        # Filter to API-relevant findings
        api_findings: list[Finding] = []
        for f in all_findings:
            is_dast = f.tool_type and f.tool_type.upper() == "DAST"
            has_api_cwe = f.cwe is not None and f.cwe in all_api_cwes
            if is_dast or has_api_cwe:
                api_findings.append(f)

        return api_findings


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _endpoint_risk_level(
    correlated_findings: list[dict[str, Any]],
    requires_auth: bool,
) -> str:
    """Determine risk level for an endpoint based on correlated findings."""
    if not correlated_findings:
        return "low" if requires_auth else "medium"

    severities = [f["severity"] for f in correlated_findings]
    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"
