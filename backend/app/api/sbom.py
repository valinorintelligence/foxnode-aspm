"""SBOM Management & AI/ML Supply Chain Security API.

Endpoints for uploading, querying, and analysing Software Bill of Materials
data, including dependency risk analysis and supply-chain threat detection.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.product import Product
from app.models.finding import Finding
from app.services.sbom_service import (
    parse_cyclonedx,
    parse_spdx,
    analyze_dependencies,
    generate_sbom_report,
    detect_supply_chain_risks,
)

router = APIRouter(prefix="/sbom", tags=["SBOM"])

# ---------------------------------------------------------------------------
# In-memory SBOM store (per-product).  In production this would be a
# dedicated database table; here we keep things simple.
# ---------------------------------------------------------------------------
_sbom_store: dict[int, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_product_or_404(product_id: int, db: AsyncSession) -> Product:
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


def _get_stored_components(product_id: int) -> list[dict[str, Any]]:
    """Return previously-uploaded components, or an empty list."""
    entry = _sbom_store.get(product_id)
    if entry:
        return entry.get("components", [])
    return []


# ═══════════════════════════════════════════════════════════════════════════
# POST  /sbom/upload/{product_id}
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/upload/{product_id}")
async def upload_sbom(
    product_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Upload a CycloneDX or SPDX JSON SBOM file for a product.

    The file is parsed, components are extracted, and a dependency
    analysis is run automatically.
    """
    product = await _get_product_or_404(product_id, db)

    # Read and parse JSON
    import json

    try:
        raw = await file.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid JSON file: {exc}",
        )

    # Detect format
    bom_format = "unknown"
    components: list[dict[str, Any]] = []

    if "bomFormat" in data or "components" in data:
        bom_format = "CycloneDX"
        components = parse_cyclonedx(data)
    elif "spdxVersion" in data or "packages" in data:
        bom_format = "SPDX"
        components = parse_spdx(data)
    else:
        raise HTTPException(
            status_code=400,
            detail="Unsupported SBOM format. Please upload CycloneDX or SPDX JSON.",
        )

    if not components:
        raise HTTPException(
            status_code=400,
            detail="No components found in the uploaded SBOM file.",
        )

    # Run dependency analysis
    analysis = analyze_dependencies(components)

    # Store
    _sbom_store[product_id] = {
        "product_id": product_id,
        "product_name": product.name,
        "format": bom_format,
        "spec_version": data.get("specVersion", data.get("spdxVersion", "")),
        "serial_number": data.get("serialNumber", ""),
        "components": components,
        "analysis": analysis,
    }

    return {
        "message": f"SBOM uploaded successfully for product '{product.name}'",
        "format": bom_format,
        "total_components": len(components),
        "analysis_summary": {
            "known_vulnerabilities": len(analysis["known_vulnerabilities"]),
            "outdated_packages": len(analysis["outdated_packages"]),
            "license_risks": len(analysis["license_risks"]),
            "typosquatting_candidates": len(analysis["typosquatting_candidates"]),
            "duplicate_dependencies": len(analysis["duplicate_dependencies"]),
            "transitive_risk_score": analysis["transitive_risk_score"],
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
# GET  /sbom/product/{product_id}
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/product/{product_id}")
async def get_sbom(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the full SBOM report for a product.

    If an SBOM has been uploaded, returns that data enriched with analysis.
    Otherwise, generates a report from mock data to demonstrate the feature.
    """
    product = await _get_product_or_404(product_id, db)

    # If we have uploaded data, return enriched version
    stored = _sbom_store.get(product_id)
    if stored:
        return {
            **stored,
            "supply_chain_risks": detect_supply_chain_risks(stored["components"]),
        }

    # Fall back to generated report
    return await generate_sbom_report(db, product_id)


# ═══════════════════════════════════════════════════════════════════════════
# GET  /sbom/components/{product_id}
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/components/{product_id}")
async def list_components(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all components / dependencies for a product's SBOM."""
    product = await _get_product_or_404(product_id, db)

    components = _get_stored_components(product_id)
    if not components:
        # Generate mock components
        from app.services.sbom_service import _generate_mock_sbom_components
        components = _generate_mock_sbom_components(product_id)

    # Summary stats
    from collections import Counter
    by_type = dict(Counter(c["type"] for c in components))
    by_ecosystem = dict(Counter(c.get("ecosystem", "unknown") for c in components))

    return {
        "product_id": product_id,
        "product_name": product.name,
        "total_components": len(components),
        "by_type": by_type,
        "by_ecosystem": by_ecosystem,
        "components": components,
    }


# ═══════════════════════════════════════════════════════════════════════════
# GET  /sbom/vulnerabilities/{product_id}
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/vulnerabilities/{product_id}")
async def get_vulnerabilities(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Vulnerability correlation for SBOM components.

    Matches component versions against known CVEs and cross-references
    with existing findings in the database.
    """
    product = await _get_product_or_404(product_id, db)

    components = _get_stored_components(product_id)
    if not components:
        from app.services.sbom_service import _generate_mock_sbom_components
        components = _generate_mock_sbom_components(product_id)

    from app.services.sbom_service import (
        _match_known_vulnerabilities,
        _correlate_with_findings,
    )

    vuln_matches = _match_known_vulnerabilities(components)
    correlation = await _correlate_with_findings(db, product_id, components)

    affected = [v for v in vuln_matches if v.get("is_affected")]
    by_severity = {}
    for v in affected:
        sev = v["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "product_id": product_id,
        "product_name": product.name,
        "total_vulnerabilities": len(affected),
        "by_severity": by_severity,
        "vulnerabilities": vuln_matches,
        "finding_correlation": correlation,
    }


# ═══════════════════════════════════════════════════════════════════════════
# GET  /sbom/licenses/{product_id}
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/licenses/{product_id}")
async def get_license_analysis(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """License compliance analysis for a product's SBOM components."""
    product = await _get_product_or_404(product_id, db)

    components = _get_stored_components(product_id)
    if not components:
        from app.services.sbom_service import _generate_mock_sbom_components
        components = _generate_mock_sbom_components(product_id)

    from app.services.sbom_service import _check_license_risks
    from collections import Counter

    # All licenses
    all_licenses: list[str] = []
    for c in components:
        all_licenses.extend(c.get("licenses", []))

    distribution = dict(Counter(all_licenses))
    risks = _check_license_risks(components)

    # Categorise
    permissive = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
                  "ISC", "Unlicense", "CC0-1.0", "MIT-CMU"]
    copyleft = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"]

    categories = {"permissive": 0, "copyleft": 0, "weak_copyleft": 0, "other": 0}
    for lic in all_licenses:
        lic_upper = lic.upper()
        if any(p.upper() in lic_upper for p in permissive):
            categories["permissive"] += 1
        elif "AGPL" in lic_upper or ("GPL" in lic_upper and "LGPL" not in lic_upper):
            categories["copyleft"] += 1
        elif "LGPL" in lic_upper:
            categories["weak_copyleft"] += 1
        else:
            categories["other"] += 1

    compliant = len(risks) == 0

    return {
        "product_id": product_id,
        "product_name": product.name,
        "total_licenses": len(all_licenses),
        "unique_licenses": len(distribution),
        "distribution": distribution,
        "categories": categories,
        "risks": risks,
        "is_compliant": compliant,
        "compliance_status": "compliant" if compliant else "review_required",
    }


# ═══════════════════════════════════════════════════════════════════════════
# GET  /sbom/supply-chain-risks/{product_id}
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/supply-chain-risks/{product_id}")
async def get_supply_chain_risks(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Supply chain risk assessment including ML model security analysis."""
    product = await _get_product_or_404(product_id, db)

    components = _get_stored_components(product_id)
    if not components:
        from app.services.sbom_service import _generate_mock_sbom_components
        components = _generate_mock_sbom_components(product_id)

    risks = detect_supply_chain_risks(components)

    return {
        "product_id": product_id,
        "product_name": product.name,
        "total_components_analyzed": len(components),
        **risks,
    }


# ═══════════════════════════════════════════════════════════════════════════
# GET  /sbom/overview
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/overview")
async def get_sbom_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Org-wide SBOM statistics across all products."""
    products_result = await db.execute(select(Product).order_by(Product.name))
    products = products_result.scalars().all()

    if not products:
        return {
            "total_products": 0,
            "products_with_sbom": 0,
            "total_components": 0,
            "total_vulnerabilities": 0,
            "total_license_risks": 0,
            "total_supply_chain_issues": 0,
            "products": [],
        }

    from app.services.sbom_service import (
        _generate_mock_sbom_components,
        _match_known_vulnerabilities,
        _check_license_risks,
    )

    total_components = 0
    total_vulns = 0
    total_license_risks = 0
    total_supply_chain = 0
    products_with_sbom = 0
    product_summaries: list[dict[str, Any]] = []

    for product in products:
        components = _get_stored_components(product.id)
        has_uploaded = bool(components)
        if not components:
            components = _generate_mock_sbom_components(product.id)

        products_with_sbom += 1 if has_uploaded else 0
        total_components += len(components)

        vulns = _match_known_vulnerabilities(components)
        affected = [v for v in vulns if v.get("is_affected")]
        total_vulns += len(affected)

        lic_risks = _check_license_risks(components)
        total_license_risks += len(lic_risks)

        sc_risks = detect_supply_chain_risks(components)
        total_supply_chain += sc_risks.get("total_issues", 0)

        # Determine risk level
        risk = "low"
        if any(v["severity"] == "critical" for v in affected):
            risk = "critical"
        elif any(v["severity"] == "high" for v in affected):
            risk = "high"
        elif lic_risks:
            risk = "medium"

        product_summaries.append({
            "product_id": product.id,
            "product_name": product.name,
            "has_uploaded_sbom": has_uploaded,
            "component_count": len(components),
            "vulnerability_count": len(affected),
            "license_risk_count": len(lic_risks),
            "supply_chain_risk_level": sc_risks.get("overall_risk_level", "low"),
            "overall_risk": risk,
        })

    # Aggregate severity breakdown
    all_components: list[dict[str, Any]] = []
    for product in products:
        comps = _get_stored_components(product.id)
        if not comps:
            comps = _generate_mock_sbom_components(product.id)
        all_components.extend(comps)

    from collections import Counter
    ecosystem_dist = dict(Counter(c.get("ecosystem", "unknown") for c in all_components))
    type_dist = dict(Counter(c["type"] for c in all_components))

    return {
        "total_products": len(products),
        "products_with_sbom": products_with_sbom,
        "total_components": total_components,
        "total_vulnerabilities": total_vulns,
        "total_license_risks": total_license_risks,
        "total_supply_chain_issues": total_supply_chain,
        "ecosystem_distribution": ecosystem_dist,
        "component_type_distribution": type_dist,
        "products": product_summaries,
    }
