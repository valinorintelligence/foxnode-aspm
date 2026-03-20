import logging
from collections import defaultdict
from typing import Any, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus, Endpoint
from app.models.product import Product

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attack chain templates
# Each template defines a combination of CWEs that, when present together,
# form a real attack chain with compounded risk.
# ---------------------------------------------------------------------------

ATTACK_CHAIN_TEMPLATES: list[dict[str, Any]] = [
    {
        "name": "Account Takeover via XSS + Session Fixation",
        "description": (
            "Cross-site scripting combined with session fixation allows an attacker "
            "to hijack user sessions and take over accounts."
        ),
        "cwes": [{79}, {384}],
        "base_risk": 85,
        "likelihood": "high",
        "impact": "critical",
        "mitigation_priority": "immediate",
    },
    {
        "name": "Data Breach via SQL Injection + Sensitive Data Exposure",
        "description": (
            "SQL injection provides database access while sensitive data exposure "
            "ensures extracted data is unprotected, leading to a full data breach."
        ),
        "cwes": [{89}, {200, 311, 312, 319}],
        "base_risk": 95,
        "likelihood": "high",
        "impact": "critical",
        "mitigation_priority": "immediate",
    },
    {
        "name": "Infrastructure Compromise via SSRF + Cloud Misconfiguration",
        "description": (
            "Server-side request forgery combined with cloud misconfigurations "
            "allows lateral movement into internal cloud infrastructure."
        ),
        "cwes": [{918}, {16, 1032, 269}],
        "base_risk": 90,
        "likelihood": "medium",
        "impact": "critical",
        "mitigation_priority": "immediate",
    },
    {
        "name": "Remote Code Execution via Path Traversal + File Upload",
        "description": (
            "Unrestricted file upload combined with path traversal enables an "
            "attacker to place and execute arbitrary code on the server."
        ),
        "cwes": [{22, 23}, {434}],
        "base_risk": 92,
        "likelihood": "medium",
        "impact": "critical",
        "mitigation_priority": "immediate",
    },
    {
        "name": "Data Exfiltration via Broken Auth + IDOR",
        "description": (
            "Broken authentication allows an attacker to access the application, "
            "while insecure direct object references enable mass data extraction."
        ),
        "cwes": [{287, 306}, {639}],
        "base_risk": 80,
        "likelihood": "high",
        "impact": "high",
        "mitigation_priority": "next_sprint",
    },
    {
        "name": "Unauthorized Access via Hardcoded Credentials + Exposed Endpoint",
        "description": (
            "Hardcoded credentials discovered alongside publicly exposed endpoints "
            "grant direct unauthorized access to the application."
        ),
        "cwes": [{798, 259}, {284, 200}],
        "base_risk": 78,
        "likelihood": "high",
        "impact": "high",
        "mitigation_priority": "next_sprint",
    },
    {
        "name": "Internal Network Scanning via XXE + SSRF",
        "description": (
            "XML external entity injection combined with SSRF capabilities "
            "allows attackers to probe and map internal network infrastructure."
        ),
        "cwes": [{611}, {918}],
        "base_risk": 75,
        "likelihood": "medium",
        "impact": "high",
        "mitigation_priority": "next_sprint",
    },
    {
        "name": "Full System Compromise via Insecure Deserialization + RCE",
        "description": (
            "Insecure deserialization provides a code execution primitive that, "
            "combined with other RCE vectors, leads to full system compromise."
        ),
        "cwes": [{502}, {94, 78, 77}],
        "base_risk": 98,
        "likelihood": "medium",
        "impact": "critical",
        "mitigation_priority": "immediate",
    },
]

# Severity to numeric weight for risk calculation
SEVERITY_RISK_WEIGHT: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.05,
}


class AttackPathService:
    """Engine for discovering and visualising attack paths from finding data."""

    # ------------------------------------------------------------------
    # Core discovery
    # ------------------------------------------------------------------

    async def discover_attack_paths(
        self, db: AsyncSession, product_id: int
    ) -> list[dict[str, Any]]:
        """Query findings for a product and match CWE combinations to identify
        real attack chains based on the predefined templates.

        Returns a list of attack path objects suitable for the API response.
        """
        findings = await self._get_open_findings(db, product_id)
        if not findings:
            return []

        # Build a set of CWEs present in the product's findings and a lookup
        cwe_set: set[int] = set()
        cwe_to_findings: dict[int, list[Finding]] = defaultdict(list)
        for f in findings:
            if f.cwe is not None:
                cwe_set.add(f.cwe)
                cwe_to_findings[f.cwe].append(f)

        attack_paths: list[dict[str, Any]] = []
        path_id = 0

        for template in ATTACK_CHAIN_TEMPLATES:
            cwe_groups: list[set[int]] = template["cwes"]
            # Each group in the template requires at least one CWE match
            matched_groups: list[list[Finding]] = []
            all_matched = True

            for group in cwe_groups:
                group_findings: list[Finding] = []
                for cwe in group:
                    group_findings.extend(cwe_to_findings.get(cwe, []))
                if not group_findings:
                    all_matched = False
                    break
                matched_groups.append(group_findings)

            if not all_matched:
                continue

            path_id += 1

            # Build nodes from the matched findings (deduplicated)
            seen_ids: set[int] = set()
            nodes: list[dict[str, Any]] = []
            for group_findings in matched_groups:
                for f in group_findings:
                    if f.id not in seen_ids:
                        seen_ids.add(f.id)
                        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                        nodes.append({
                            "finding_id": f.id,
                            "title": f.title or "Untitled",
                            "severity": sev,
                            "cwe": f.cwe,
                        })

            # Build edges (chain order between groups)
            edges: list[dict[str, Any]] = []
            for i in range(len(matched_groups) - 1):
                source_ids = {f.id for f in matched_groups[i]}
                target_ids = {f.id for f in matched_groups[i + 1]}
                for src in source_ids:
                    for tgt in target_ids:
                        edges.append({
                            "source": src,
                            "target": tgt,
                            "relationship": "enables",
                        })

            # Adjust risk score based on finding severities
            max_sev_weight = max(
                SEVERITY_RISK_WEIGHT.get(
                    n["severity"], 0.3
                )
                for n in nodes
            ) if nodes else 0.5
            risk_score = min(100, int(template["base_risk"] * max_sev_weight * 1.1))

            attack_paths.append({
                "id": path_id,
                "name": template["name"],
                "description": template["description"],
                "risk_score": risk_score,
                "nodes": nodes,
                "edges": edges,
                "likelihood": template["likelihood"],
                "impact": template["impact"],
                "mitigation_priority": template["mitigation_priority"],
            })

        # Sort by risk score descending
        attack_paths.sort(key=lambda p: p["risk_score"], reverse=True)
        return attack_paths

    # ------------------------------------------------------------------
    # Attack surface mapping
    # ------------------------------------------------------------------

    async def get_attack_surface(
        self, db: AsyncSession, product_id: int
    ) -> dict[str, Any]:
        """Map the attack surface for a product by categorising findings
        into entry points, internal weaknesses, data stores, and external services.
        """
        findings = await self._get_open_findings(db, product_id)

        entry_points: list[dict[str, Any]] = []
        internal_weaknesses: list[dict[str, Any]] = []
        data_stores: list[dict[str, Any]] = []
        external_services: list[dict[str, Any]] = []

        # CWEs that indicate data-store related issues
        data_store_cwes = {89, 312, 311, 522, 256, 257, 327}
        # CWEs that indicate external-service / SSRF / API issues
        external_cwes = {918, 441, 611, 352}

        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            summary = {
                "finding_id": f.id,
                "title": f.title or "Untitled",
                "severity": sev,
                "cwe": f.cwe,
                "tool_type": f.tool_type,
            }

            # DAST findings represent externally-reachable entry points
            if f.tool_type and f.tool_type.upper() == "DAST":
                entry_points.append(summary)
            # SAST findings represent internal code weaknesses
            elif f.tool_type and f.tool_type.upper() == "SAST":
                internal_weaknesses.append(summary)
            # Classify by CWE
            elif f.cwe and f.cwe in data_store_cwes:
                data_stores.append(summary)
            elif f.cwe and f.cwe in external_cwes:
                external_services.append(summary)
            else:
                # Default to internal weakness
                internal_weaknesses.append(summary)

            # Additionally tag data-store and external CWEs even if from SAST/DAST
            if f.cwe and f.cwe in data_store_cwes and summary not in data_stores:
                data_stores.append(summary)
            if f.cwe and f.cwe in external_cwes and summary not in external_services:
                external_services.append(summary)

        # Pull in endpoints from the Endpoint model for richer surface data
        endpoint_query = (
            select(Endpoint)
            .where(Endpoint.product_id == product_id)
        )
        result = await db.execute(endpoint_query)
        endpoints = result.scalars().all()

        endpoint_list = [
            {
                "id": ep.id,
                "host": ep.host,
                "path": ep.path,
                "port": ep.port,
                "protocol": ep.protocol,
            }
            for ep in endpoints
        ]

        return {
            "product_id": product_id,
            "total_findings": len(findings),
            "entry_points": entry_points,
            "internal_weaknesses": internal_weaknesses,
            "data_stores": data_stores,
            "external_services": external_services,
            "discovered_endpoints": endpoint_list,
            "summary": {
                "entry_point_count": len(entry_points),
                "internal_weakness_count": len(internal_weaknesses),
                "data_store_count": len(data_stores),
                "external_service_count": len(external_services),
                "endpoint_count": len(endpoint_list),
            },
        }

    # ------------------------------------------------------------------
    # Graph data for frontend visualisation
    # ------------------------------------------------------------------

    async def calculate_risk_graph(
        self, db: AsyncSession, product_id: int
    ) -> dict[str, Any]:
        """Return nodes and edges suitable for frontend graph visualisation.

        Builds a graph from attack paths where each finding is a node and
        edges represent enablement relationships in the attack chain.
        """
        attack_paths = await self.discover_attack_paths(db, product_id)

        graph_nodes: dict[int, dict[str, Any]] = {}
        graph_edges: list[dict[str, Any]] = []
        edge_set: set[tuple[int, int]] = set()

        for path in attack_paths:
            for node in path["nodes"]:
                fid = node["finding_id"]
                if fid not in graph_nodes:
                    graph_nodes[fid] = {
                        "id": fid,
                        "label": node["title"],
                        "severity": node["severity"],
                        "cwe": node["cwe"],
                        "attack_paths": [],
                    }
                graph_nodes[fid]["attack_paths"].append(path["name"])

            for edge in path["edges"]:
                key = (edge["source"], edge["target"])
                if key not in edge_set:
                    edge_set.add(key)
                    graph_edges.append({
                        "source": edge["source"],
                        "target": edge["target"],
                        "relationship": edge["relationship"],
                        "attack_path": path["name"],
                    })

        return {
            "product_id": product_id,
            "nodes": list(graph_nodes.values()),
            "edges": graph_edges,
            "total_paths": len(attack_paths),
            "highest_risk": attack_paths[0]["risk_score"] if attack_paths else 0,
        }

    # ------------------------------------------------------------------
    # Org-wide overview
    # ------------------------------------------------------------------

    async def get_overview(
        self, db: AsyncSession
    ) -> dict[str, Any]:
        """Org-wide attack path summary across all products."""
        products_result = await db.execute(select(Product).order_by(Product.name))
        products = products_result.scalars().all()

        total_paths = 0
        critical_paths = 0
        products_at_risk: list[dict[str, Any]] = []

        for product in products:
            paths = await self.discover_attack_paths(db, product.id)
            if paths:
                total_paths += len(paths)
                crit = sum(1 for p in paths if p["risk_score"] >= 80)
                critical_paths += crit
                products_at_risk.append({
                    "product_id": product.id,
                    "product_name": product.name,
                    "attack_path_count": len(paths),
                    "critical_paths": crit,
                    "highest_risk_score": paths[0]["risk_score"],
                    "top_path": paths[0]["name"],
                })

        products_at_risk.sort(key=lambda p: p["highest_risk_score"], reverse=True)

        return {
            "total_attack_paths": total_paths,
            "critical_paths": critical_paths,
            "products_at_risk": len(products_at_risk),
            "total_products": len(products),
            "product_breakdown": products_at_risk,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _get_open_findings(
        db: AsyncSession, product_id: int
    ) -> list[Finding]:
        """Fetch open (non-duplicate) findings for a product."""
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
        return list(result.scalars().all())
