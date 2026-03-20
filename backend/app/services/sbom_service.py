"""SBOM Management & AI/ML Supply Chain Security engine.

Provides parsing for CycloneDX and SPDX formats, dependency analysis,
vulnerability correlation, license compliance checking, and supply-chain
risk detection (including ML model poisoning indicators).
"""

import hashlib
import logging
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity
from app.models.product import Product

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known-vulnerability mock database (simulates NVD / OSV lookup)
# ---------------------------------------------------------------------------

KNOWN_VULNERABLE_PACKAGES: dict[str, list[dict[str, Any]]] = {
    "lodash": [
        {"cve": "CVE-2021-23337", "severity": "high", "fixed_in": "4.17.21",
         "summary": "Command injection via template function"},
        {"cve": "CVE-2020-28500", "severity": "medium", "fixed_in": "4.17.21",
         "summary": "ReDoS in toNumber, trim, trimEnd"},
    ],
    "express": [
        {"cve": "CVE-2024-29041", "severity": "medium", "fixed_in": "4.19.2",
         "summary": "Open redirect via URL parsing"},
    ],
    "axios": [
        {"cve": "CVE-2023-45857", "severity": "high", "fixed_in": "1.6.0",
         "summary": "CSRF token exposure via XSRF-TOKEN cookie"},
    ],
    "jsonwebtoken": [
        {"cve": "CVE-2022-23529", "severity": "critical", "fixed_in": "9.0.0",
         "summary": "Insecure key retrieval allows JWT forgery"},
    ],
    "pytorch": [
        {"cve": "CVE-2024-31583", "severity": "high", "fixed_in": "2.2.0",
         "summary": "Arbitrary code execution via torch.load with pickle"},
    ],
    "tensorflow": [
        {"cve": "CVE-2023-25801", "severity": "critical", "fixed_in": "2.12.0",
         "summary": "OOB read in TFLite GPU delegate"},
        {"cve": "CVE-2023-25660", "severity": "high", "fixed_in": "2.12.0",
         "summary": "Heap buffer overflow in AvgPool3DGrad"},
    ],
    "numpy": [
        {"cve": "CVE-2021-33430", "severity": "medium", "fixed_in": "1.22.0",
         "summary": "Buffer overflow in array_from_pyobj"},
    ],
    "pillow": [
        {"cve": "CVE-2023-44271", "severity": "high", "fixed_in": "10.0.0",
         "summary": "Denial of service via uncontrolled resource consumption"},
    ],
    "requests": [
        {"cve": "CVE-2023-32681", "severity": "medium", "fixed_in": "2.31.0",
         "summary": "Leaking Proxy-Authorization header to redirected hosts"},
    ],
    "django": [
        {"cve": "CVE-2024-27351", "severity": "high", "fixed_in": "4.2.11",
         "summary": "ReDoS in django.utils.text.Truncator"},
    ],
    "flask": [
        {"cve": "CVE-2023-30861", "severity": "high", "fixed_in": "2.3.2",
         "summary": "Cookie caching on shared proxies allows session hijacking"},
    ],
    "transformers": [
        {"cve": "CVE-2023-47115", "severity": "critical", "fixed_in": "4.36.0",
         "summary": "Arbitrary code execution via crafted model files"},
    ],
    "scikit-learn": [
        {"cve": "CVE-2020-28975", "severity": "medium", "fixed_in": "0.24.0",
         "summary": "Denial of service via malicious pickle model"},
    ],
    "onnx": [
        {"cve": "CVE-2024-27318", "severity": "high", "fixed_in": "1.16.0",
         "summary": "Directory traversal in ONNX model extraction"},
    ],
}

# ---------------------------------------------------------------------------
# Known malicious / typosquat packages
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS_PACKAGES: set[str] = {
    "event-stream",          # compromised via flatmap-stream
    "ua-parser-js",          # 0.7.29 supply-chain attack
    "coa",                   # compromised npm package
    "rc",                    # compromised npm package
    "colors",               # protestware (v1.4.1+)
    "faker",                # protestware (v6.6.6)
    "node-ipc",             # protestware / peacenotwar
    "flatmap-stream",       # Bitcoin-stealing malware
    "crossenv",             # credential-stealing typosquat
    "cross-env.js",         # credential-stealing typosquat
    "mongose",              # typosquat of mongoose
    "babelcli",             # typosquat of babel-cli
    "d3.js",               # typosquat of d3
    "gruntcli",            # typosquat of grunt-cli
    "http-proxy.js",       # typosquat of http-proxy
    "jquery.js",           # typosquat of jquery
    "mariadb",             # malicious npm package (not the real one)
    "mysqljs",             # typosquat of mysql
    "node-fabric",         # typosquat of fabric
    "node-opencv",         # malicious binding
    "nodefabric",          # typosquat
    "noderequest",         # typosquat of request
    "nodesass",            # typosquat of node-sass
    "openai-fake",         # hypothetical ML supply chain attack
    "pytorch-nightly-malicious",  # hypothetical
    "tf-nightly-gpu-fake",       # hypothetical
}

# Popular packages used as reference for typosquatting detection
POPULAR_PACKAGES: set[str] = {
    "lodash", "express", "react", "vue", "angular", "axios", "moment",
    "chalk", "debug", "commander", "inquirer", "webpack", "babel",
    "eslint", "prettier", "jest", "mocha", "typescript", "underscore",
    "async", "bluebird", "request", "node-fetch", "mongoose", "sequelize",
    "redis", "pg", "mysql", "sqlite3", "cors", "helmet", "passport",
    "jsonwebtoken", "bcrypt", "dotenv", "uuid", "yargs", "glob",
    "tensorflow", "pytorch", "numpy", "pandas", "scikit-learn",
    "transformers", "keras", "scipy", "matplotlib", "opencv-python",
    "pillow", "flask", "django", "fastapi", "sqlalchemy", "celery",
    "boto3", "openai", "langchain", "huggingface-hub", "onnx",
    "onnxruntime", "torch", "torchvision", "torchaudio",
}

# Restrictive / copyleft licenses that may pose risk in commercial use
RESTRICTIVE_LICENSES: set[str] = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-1.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
    "SSPL-1.0", "EUPL-1.1", "EUPL-1.2",
    "CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0",
}

# ML-specific file extensions and patterns
ML_MODEL_EXTENSIONS: set[str] = {
    ".pkl", ".pickle", ".pt", ".pth", ".h5", ".hdf5",
    ".onnx", ".pb", ".tflite", ".safetensors", ".bin",
    ".ckpt", ".model", ".joblib", ".npy", ".npz",
}


# ═══════════════════════════════════════════════════════════════════════════
# CycloneDX Parser
# ═══════════════════════════════════════════════════════════════════════════

def parse_cyclonedx(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a CycloneDX BOM JSON and extract component metadata.

    Handles CycloneDX 1.4 / 1.5 / 1.6 formats.  Returns a flat list of
    component dicts with normalised keys.
    """
    components: list[dict[str, Any]] = []

    raw_components = data.get("components", [])

    for comp in raw_components:
        # Licenses can appear as expression or list of license objects
        licenses_raw = comp.get("licenses", [])
        license_ids: list[str] = []
        for lic in licenses_raw:
            if "license" in lic:
                license_ids.append(
                    lic["license"].get("id") or lic["license"].get("name", "Unknown")
                )
            elif "expression" in lic:
                license_ids.append(lic["expression"])

        # Hashes
        hashes_raw = comp.get("hashes", [])
        hashes: dict[str, str] = {}
        for h in hashes_raw:
            hashes[h.get("alg", "unknown")] = h.get("content", "")

        # External references (useful for ML model provenance)
        ext_refs = comp.get("externalReferences", [])
        model_card_url = None
        for ref in ext_refs:
            if ref.get("type") in ("model-card", "documentation"):
                model_card_url = ref.get("url")
                break

        parsed = {
            "name": comp.get("name", "unknown"),
            "version": comp.get("version", ""),
            "type": comp.get("type", "library"),          # library, framework, application, etc.
            "purl": comp.get("purl", ""),
            "group": comp.get("group", ""),
            "publisher": comp.get("publisher", ""),
            "scope": comp.get("scope", "required"),        # required | optional | excluded
            "licenses": license_ids,
            "hashes": hashes,
            "description": comp.get("description", ""),
            "bom_ref": comp.get("bom-ref", ""),
            "cpe": comp.get("cpe", ""),
            "model_card_url": model_card_url,
        }

        # Infer language / ecosystem from purl
        parsed["ecosystem"] = _ecosystem_from_purl(parsed["purl"])

        components.append(parsed)

    return components


# ═══════════════════════════════════════════════════════════════════════════
# SPDX Parser
# ═══════════════════════════════════════════════════════════════════════════

def parse_spdx(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse an SPDX 2.3 JSON document and extract package metadata.

    Maps SPDX package fields to the same normalised schema used by
    the CycloneDX parser so downstream analysis is format-agnostic.
    """
    components: list[dict[str, Any]] = []

    packages = data.get("packages", [])

    for pkg in packages:
        # Skip the document-describes root package
        spdx_id = pkg.get("SPDXID", "")
        if spdx_id == "SPDXRef-DOCUMENT":
            continue

        # License: prefer concludedLicense, fall back to declaredLicense
        license_concluded = pkg.get("licenseConcluded", "NOASSERTION")
        license_declared = pkg.get("licenseDeclared", "NOASSERTION")
        license_str = license_concluded if license_concluded != "NOASSERTION" else license_declared
        license_ids = [license_str] if license_str and license_str != "NOASSERTION" else []

        # Checksums
        hashes: dict[str, str] = {}
        for cs in pkg.get("checksums", []):
            hashes[cs.get("algorithm", "unknown")] = cs.get("checksumValue", "")

        # External refs -> purl
        purl = ""
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break

        parsed = {
            "name": pkg.get("name", "unknown"),
            "version": pkg.get("versionInfo", ""),
            "type": "library",
            "purl": purl,
            "group": "",
            "publisher": pkg.get("supplier", pkg.get("originator", "")),
            "scope": "required",
            "licenses": license_ids,
            "hashes": hashes,
            "description": pkg.get("description", pkg.get("summary", "")),
            "bom_ref": spdx_id,
            "cpe": "",
            "model_card_url": None,
        }

        parsed["ecosystem"] = _ecosystem_from_purl(purl)

        components.append(parsed)

    return components


# ═══════════════════════════════════════════════════════════════════════════
# Dependency analysis
# ═══════════════════════════════════════════════════════════════════════════

def analyze_dependencies(components: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyse a dependency list and return a structured risk assessment.

    Returns:
        Dict with keys:
        - known_vulnerabilities
        - outdated_packages
        - license_risks
        - typosquatting_candidates
        - duplicate_dependencies
        - transitive_risk_score
    """

    known_vulns = _match_known_vulnerabilities(components)
    outdated = _detect_outdated_packages(components)
    license_risks = _check_license_risks(components)
    typosquat = _detect_typosquatting(components)
    duplicates = _find_duplicate_dependencies(components)
    transitive_score = _compute_transitive_risk_score(
        components, known_vulns, typosquat, license_risks
    )

    return {
        "known_vulnerabilities": known_vulns,
        "outdated_packages": outdated,
        "license_risks": license_risks,
        "typosquatting_candidates": typosquat,
        "duplicate_dependencies": duplicates,
        "transitive_risk_score": transitive_score,
        "total_components": len(components),
    }


# ═══════════════════════════════════════════════════════════════════════════
# SBOM report generation
# ═══════════════════════════════════════════════════════════════════════════

async def generate_sbom_report(
    db: AsyncSession, product_id: int
) -> dict[str, Any]:
    """Generate a comprehensive SBOM report for a product.

    Correlates SBOM component data with existing findings in the database
    to provide a holistic view of the software composition.
    """
    # Fetch product
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        return {"error": "Product not found"}

    # In a real system, components would be stored in a dedicated table.
    # Here we generate representative mock data seeded by product_id.
    components = _generate_mock_sbom_components(product_id)

    # Classify by type
    by_type: dict[str, int] = Counter(c["type"] for c in components)

    # Classify by language/ecosystem
    by_language: dict[str, int] = Counter(c["ecosystem"] for c in components)

    # License distribution
    all_licenses: list[str] = []
    for c in components:
        all_licenses.extend(c["licenses"])
    license_distribution = dict(Counter(all_licenses))

    # Vulnerability correlation with existing findings
    vuln_correlation = await _correlate_with_findings(db, product_id, components)

    # Dependency analysis
    dep_analysis = analyze_dependencies(components)

    # Supply chain risks
    supply_chain = detect_supply_chain_risks(components)

    return {
        "product_id": product_id,
        "product_name": product.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_components": len(components),
        "by_type": dict(by_type),
        "by_language": dict(by_language),
        "license_distribution": license_distribution,
        "vulnerability_correlation": vuln_correlation,
        "dependency_analysis": dep_analysis,
        "supply_chain_risks": supply_chain,
        "risk_summary": _build_risk_summary(dep_analysis, supply_chain),
        "components": components,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Supply chain risk detection
# ═══════════════════════════════════════════════════════════════════════════

def detect_supply_chain_risks(
    components: list[dict[str, Any]],
) -> dict[str, Any]:
    """Detect supply-chain risks including ML-specific threats.

    Checks for:
    - Known malicious packages
    - Typosquatting patterns
    - Packages with suspicious install scripts (heuristic)
    - Packages with very few downloads / new accounts (simulated)
    - ML model poisoning indicators
    """

    malicious_hits: list[dict[str, Any]] = []
    typosquat_hits: list[dict[str, Any]] = []
    suspicious_scripts: list[dict[str, Any]] = []
    low_reputation: list[dict[str, Any]] = []
    ml_risks: list[dict[str, Any]] = []

    for comp in components:
        name_lower = comp["name"].lower()

        # --- Known malicious ---
        if name_lower in KNOWN_MALICIOUS_PACKAGES:
            malicious_hits.append({
                "package": comp["name"],
                "version": comp["version"],
                "risk": "known_malicious",
                "severity": "critical",
                "detail": f"Package '{comp['name']}' is on the known-malicious registry.",
            })

        # --- Typosquatting ---
        for popular in POPULAR_PACKAGES:
            if name_lower == popular:
                continue
            similarity = SequenceMatcher(None, name_lower, popular).ratio()
            if 0.80 <= similarity < 1.0:
                typosquat_hits.append({
                    "package": comp["name"],
                    "similar_to": popular,
                    "similarity": round(similarity, 3),
                    "severity": "high",
                    "detail": f"'{comp['name']}' is suspiciously similar to popular package '{popular}'.",
                })
                break  # one match per component is enough

        # --- Suspicious install scripts (heuristic: names containing
        #     patterns that suggest post-install exfiltration) ---
        suspicious_name_patterns = [
            r"postinstall", r"preinstall", r"-hook$", r"setup-",
        ]
        for pattern in suspicious_name_patterns:
            if re.search(pattern, name_lower):
                suspicious_scripts.append({
                    "package": comp["name"],
                    "severity": "medium",
                    "detail": f"Package name matches suspicious install-script pattern: {pattern}",
                })
                break

        # --- Low reputation (simulated) ---
        # Use deterministic hash to decide if a package is "new / low download"
        rep_hash = int(hashlib.md5(name_lower.encode()).hexdigest()[:8], 16)
        if rep_hash % 100 < 5:  # ~5% of packages flagged
            low_reputation.append({
                "package": comp["name"],
                "severity": "medium",
                "detail": "Package has limited download history and a recently-created publisher account.",
                "estimated_weekly_downloads": rep_hash % 500,
                "account_age_days": rep_hash % 90,
            })

        # --- ML model poisoning indicators ---
        ml_risk = _check_ml_risks(comp)
        if ml_risk:
            ml_risks.append(ml_risk)

    risk_level = "low"
    if malicious_hits:
        risk_level = "critical"
    elif typosquat_hits or ml_risks:
        risk_level = "high"
    elif suspicious_scripts or low_reputation:
        risk_level = "medium"

    return {
        "overall_risk_level": risk_level,
        "malicious_packages": malicious_hits,
        "typosquatting_candidates": typosquat_hits,
        "suspicious_install_scripts": suspicious_scripts,
        "low_reputation_packages": low_reputation,
        "ml_model_risks": ml_risks,
        "total_issues": (
            len(malicious_hits) + len(typosquat_hits)
            + len(suspicious_scripts) + len(low_reputation) + len(ml_risks)
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════════════

def _ecosystem_from_purl(purl: str) -> str:
    """Extract the ecosystem/language from a Package URL."""
    if not purl:
        return "unknown"
    # purl format: pkg:<type>/<namespace>/<name>@<version>
    match = re.match(r"pkg:(\w+)/", purl)
    if match:
        mapping = {
            "npm": "javascript",
            "pypi": "python",
            "maven": "java",
            "nuget": "csharp",
            "golang": "go",
            "cargo": "rust",
            "gem": "ruby",
            "composer": "php",
            "swift": "swift",
            "cocoapods": "swift",
            "hex": "elixir",
            "pub": "dart",
            "cran": "r",
            "conda": "python",
            "huggingface": "python",
            "docker": "container",
        }
        return mapping.get(match.group(1), match.group(1))
    return "unknown"


def _match_known_vulnerabilities(
    components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Match components against the known-vulnerability database."""
    results: list[dict[str, Any]] = []

    for comp in components:
        name_lower = comp["name"].lower()
        vulns = KNOWN_VULNERABLE_PACKAGES.get(name_lower, [])
        for vuln in vulns:
            fixed_in = vuln.get("fixed_in", "")
            is_affected = _version_less_than(comp["version"], fixed_in) if fixed_in else True
            results.append({
                "package": comp["name"],
                "version": comp["version"],
                "cve": vuln["cve"],
                "severity": vuln["severity"],
                "summary": vuln["summary"],
                "fixed_in": fixed_in,
                "is_affected": is_affected,
            })

    return results


def _version_less_than(current: str, target: str) -> bool:
    """Naive semver comparison — returns True if current < target."""
    try:
        curr_parts = [int(x) for x in re.split(r"[.\-+]", current) if x.isdigit()]
        tgt_parts = [int(x) for x in re.split(r"[.\-+]", target) if x.isdigit()]
        # Pad to equal length
        max_len = max(len(curr_parts), len(tgt_parts))
        curr_parts.extend([0] * (max_len - len(curr_parts)))
        tgt_parts.extend([0] * (max_len - len(tgt_parts)))
        return curr_parts < tgt_parts
    except (ValueError, TypeError):
        return False


def _detect_outdated_packages(
    components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flag packages that appear to be running old major versions.

    Uses a simple heuristic: if the major version is 0 or the version
    string suggests a version more than 2 major versions behind the
    known-vuln fixed_in, flag it.
    """
    outdated: list[dict[str, Any]] = []

    # Build a map of "latest known" from our vuln DB
    latest_known: dict[str, str] = {}
    for pkg_name, vulns in KNOWN_VULNERABLE_PACKAGES.items():
        for v in vulns:
            fi = v.get("fixed_in", "")
            if fi and (pkg_name not in latest_known or _version_less_than(latest_known[pkg_name], fi)):
                latest_known[pkg_name] = fi

    for comp in components:
        name_lower = comp["name"].lower()
        if name_lower in latest_known:
            if _version_less_than(comp["version"], latest_known[name_lower]):
                outdated.append({
                    "package": comp["name"],
                    "current_version": comp["version"],
                    "recommended_version": latest_known[name_lower],
                    "severity": "medium",
                    "detail": f"Version {comp['version']} is older than the recommended {latest_known[name_lower]}.",
                })
        # Also flag very old looking versions (0.x or 1.x for well-known packages)
        elif name_lower in POPULAR_PACKAGES:
            try:
                major = int(comp["version"].split(".")[0]) if comp["version"] else -1
            except (ValueError, IndexError):
                major = -1
            if major == 0:
                outdated.append({
                    "package": comp["name"],
                    "current_version": comp["version"],
                    "recommended_version": "latest stable",
                    "severity": "low",
                    "detail": "Package is at a 0.x pre-release version.",
                })

    return outdated


def _check_license_risks(
    components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Identify components with restrictive / copyleft licenses."""
    risks: list[dict[str, Any]] = []

    for comp in components:
        for lic in comp.get("licenses", []):
            lic_upper = lic.upper().replace(" ", "-")
            for restrictive in RESTRICTIVE_LICENSES:
                if restrictive.upper() in lic_upper:
                    severity = "high" if "AGPL" in lic_upper else "medium"
                    risks.append({
                        "package": comp["name"],
                        "version": comp["version"],
                        "license": lic,
                        "risk_type": "copyleft" if "GPL" in lic_upper else "restrictive",
                        "severity": severity,
                        "detail": (
                            f"License '{lic}' may impose copyleft obligations "
                            f"on proprietary / commercial software."
                        ),
                    })
                    break

    return risks


def _detect_typosquatting(
    components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Detect potential typosquatting among component names."""
    candidates: list[dict[str, Any]] = []
    comp_names = {c["name"].lower() for c in components}

    for comp in components:
        name = comp["name"].lower()
        if name in POPULAR_PACKAGES:
            continue  # It IS the popular package

        for popular in POPULAR_PACKAGES:
            if name == popular:
                continue

            # Check edit-distance similarity
            similarity = SequenceMatcher(None, name, popular).ratio()
            if 0.80 <= similarity < 1.0:
                candidates.append({
                    "package": comp["name"],
                    "similar_to": popular,
                    "similarity": round(similarity, 3),
                    "installed_version": comp["version"],
                    "risk": "high",
                })
                break

        # Extra heuristic: common typosquat patterns
        for popular in POPULAR_PACKAGES:
            patterns = [
                popular.replace("-", ""),       # e.g. "node-fetch" -> "nodefetch"
                popular + "js",                  # e.g. "mysql" -> "mysqljs"
                popular + ".js",                 # e.g. "jquery" -> "jquery.js"
                popular.replace("-", "."),       # e.g. "http-proxy" -> "http.proxy"
            ]
            if name in patterns and name != popular:
                if not any(c["package"].lower() == name for c in candidates):
                    candidates.append({
                        "package": comp["name"],
                        "similar_to": popular,
                        "similarity": 0.85,
                        "installed_version": comp["version"],
                        "risk": "high",
                    })
                break

    return candidates


def _find_duplicate_dependencies(
    components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Find packages that appear multiple times with different versions."""
    name_versions: dict[str, list[str]] = defaultdict(list)
    for comp in components:
        name_versions[comp["name"].lower()].append(comp["version"])

    duplicates: list[dict[str, Any]] = []
    for name, versions in name_versions.items():
        if len(versions) > 1:
            duplicates.append({
                "package": name,
                "versions": sorted(set(versions)),
                "count": len(versions),
                "risk": "low",
                "detail": "Multiple versions of the same package increase attack surface.",
            })

    return duplicates


def _compute_transitive_risk_score(
    components: list[dict[str, Any]],
    known_vulns: list[dict[str, Any]],
    typosquat: list[dict[str, Any]],
    license_risks: list[dict[str, Any]],
) -> float:
    """Compute a 0-100 transitive risk score.

    Higher score = more risk.
    """
    score = 0.0

    # Vulnerability contribution
    severity_weights = {"critical": 15, "high": 8, "medium": 4, "low": 1}
    for vuln in known_vulns:
        if vuln.get("is_affected"):
            score += severity_weights.get(vuln["severity"], 2)

    # Typosquatting contribution
    score += len(typosquat) * 10

    # License risk contribution
    score += len(license_risks) * 3

    # Scale by component count (larger dependency trees = higher base risk)
    if len(components) > 100:
        score += 5
    if len(components) > 500:
        score += 10

    return min(round(score, 1), 100.0)


def _check_ml_risks(comp: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Check a single component for ML-specific supply chain risks."""
    name_lower = comp["name"].lower()
    ml_keywords = {"model", "torch", "tensorflow", "tf", "onnx", "keras",
                   "transformers", "huggingface", "ml", "ai", "neural",
                   "bert", "gpt", "llm", "diffusion", "stable-diffusion"}

    is_ml = any(kw in name_lower for kw in ml_keywords)
    if not is_ml:
        return None

    risks: list[str] = []

    # Check for pickle-based serialization (unsafe deserialization)
    if any(ext in name_lower for ext in [".pkl", ".pickle", "pickle"]):
        risks.append("Uses pickle serialization which allows arbitrary code execution on load")

    # Check for missing model card / provenance
    if not comp.get("model_card_url"):
        risks.append("No model card or provenance documentation found")

    # Check for missing hashes (integrity verification)
    if not comp.get("hashes"):
        risks.append("No integrity hashes provided — cannot verify model has not been tampered with")

    # Flag torch.load / unsafe deserialization patterns in known packages
    if name_lower in ("pytorch", "torch") and comp.get("version"):
        if _version_less_than(comp["version"], "2.0.0"):
            risks.append("PyTorch < 2.0 defaults to unsafe pickle deserialization in torch.load()")

    # Flag transformers without pinned revision
    if "transformers" in name_lower:
        risks.append("Ensure model downloads use pinned revision hashes to prevent model swapping")

    if not risks:
        return None

    return {
        "package": comp["name"],
        "version": comp["version"],
        "severity": "high",
        "category": "ml_supply_chain",
        "risks": risks,
        "recommendation": (
            "Use SafeTensors format where possible. Pin model revisions by hash. "
            "Verify model checksums before loading. Avoid pickle deserialization "
            "of untrusted models."
        ),
    }


async def _correlate_with_findings(
    db: AsyncSession,
    product_id: int,
    components: list[dict[str, Any]],
) -> dict[str, Any]:
    """Cross-reference SBOM components with existing findings for the product."""

    # Get SCA-type findings for this product
    query = (
        select(Finding)
        .where(
            Finding.product_id == product_id,
            Finding.tool_type.in_(["SCA", "SBOM", "Dependency Check"]),
        )
    )
    result = await db.execute(query)
    sca_findings = result.scalars().all()

    # Also get findings that reference specific components
    component_names = {c["name"].lower() for c in components}
    query2 = (
        select(Finding)
        .where(
            Finding.product_id == product_id,
            Finding.component.isnot(None),
        )
    )
    result2 = await db.execute(query2)
    component_findings = result2.scalars().all()

    matched_findings: list[dict[str, Any]] = []
    for f in list(sca_findings) + list(component_findings):
        if f.component and f.component.lower() in component_names:
            matched_findings.append({
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity.value if f.severity else "unknown",
                "status": f.status.value if f.status else "unknown",
                "component": f.component,
                "component_version": f.component_version,
                "cve": f.cve,
            })

    # Known-vuln matches from our mock DB
    vuln_matches = _match_known_vulnerabilities(components)
    affected_vulns = [v for v in vuln_matches if v.get("is_affected")]

    return {
        "matched_findings_count": len(matched_findings),
        "matched_findings": matched_findings[:50],  # cap output
        "known_vuln_matches": len(affected_vulns),
        "known_vulnerabilities": affected_vulns[:50],
        "unmatched_components": len(components) - len({
            f["component"].lower()
            for f in matched_findings
            if f.get("component")
        }),
    }


def _build_risk_summary(
    dep_analysis: dict[str, Any],
    supply_chain: dict[str, Any],
) -> dict[str, Any]:
    """Build a human-readable risk summary from analysis results."""
    critical_count = sum(
        1 for v in dep_analysis.get("known_vulnerabilities", [])
        if v.get("severity") == "critical" and v.get("is_affected")
    )
    high_count = sum(
        1 for v in dep_analysis.get("known_vulnerabilities", [])
        if v.get("severity") == "high" and v.get("is_affected")
    )

    overall = "low"
    if critical_count > 0 or supply_chain.get("overall_risk_level") == "critical":
        overall = "critical"
    elif high_count > 0 or supply_chain.get("overall_risk_level") == "high":
        overall = "high"
    elif dep_analysis.get("license_risks") or dep_analysis.get("outdated_packages"):
        overall = "medium"

    recommendations: list[str] = []
    if critical_count:
        recommendations.append(
            f"Immediately patch {critical_count} critical vulnerability/ies."
        )
    if high_count:
        recommendations.append(
            f"Remediate {high_count} high-severity vulnerability/ies within 7 days."
        )
    if dep_analysis.get("typosquatting_candidates"):
        recommendations.append(
            "Investigate potential typosquatting packages before they enter production."
        )
    if dep_analysis.get("license_risks"):
        recommendations.append(
            "Review copyleft-licensed dependencies for commercial compatibility."
        )
    if supply_chain.get("ml_model_risks"):
        recommendations.append(
            "Audit ML model provenance and switch to SafeTensors format where possible."
        )
    if dep_analysis.get("outdated_packages"):
        recommendations.append(
            "Update outdated packages to their recommended versions."
        )
    if not recommendations:
        recommendations.append("Supply chain posture is healthy. Continue regular SBOM monitoring.")

    return {
        "overall_risk": overall,
        "critical_vulnerabilities": critical_count,
        "high_vulnerabilities": high_count,
        "total_license_risks": len(dep_analysis.get("license_risks", [])),
        "total_supply_chain_issues": supply_chain.get("total_issues", 0),
        "transitive_risk_score": dep_analysis.get("transitive_risk_score", 0),
        "recommendations": recommendations,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Mock SBOM component generator (used when no real SBOM is uploaded)
# ═══════════════════════════════════════════════════════════════════════════

def _generate_mock_sbom_components(product_id: int) -> list[dict[str, Any]]:
    """Generate a realistic set of SBOM components seeded by product_id.

    Produces a mix of common libraries, frameworks, and ML packages to
    demonstrate the full analysis pipeline.
    """
    rng = random.Random(product_id * 42)

    base_components = [
        {"name": "express", "version": "4.18.2", "type": "framework",
         "purl": "pkg:npm/express@4.18.2", "licenses": ["MIT"]},
        {"name": "lodash", "version": "4.17.20", "type": "library",
         "purl": "pkg:npm/lodash@4.17.20", "licenses": ["MIT"]},
        {"name": "axios", "version": "1.4.0", "type": "library",
         "purl": "pkg:npm/axios@1.4.0", "licenses": ["MIT"]},
        {"name": "jsonwebtoken", "version": "8.5.1", "type": "library",
         "purl": "pkg:npm/jsonwebtoken@8.5.1", "licenses": ["MIT"]},
        {"name": "react", "version": "18.2.0", "type": "framework",
         "purl": "pkg:npm/react@18.2.0", "licenses": ["MIT"]},
        {"name": "typescript", "version": "5.3.3", "type": "library",
         "purl": "pkg:npm/typescript@5.3.3", "licenses": ["Apache-2.0"]},
        {"name": "webpack", "version": "5.89.0", "type": "library",
         "purl": "pkg:npm/webpack@5.89.0", "licenses": ["MIT"]},
        {"name": "django", "version": "4.2.7", "type": "framework",
         "purl": "pkg:pypi/django@4.2.7", "licenses": ["BSD-3-Clause"]},
        {"name": "flask", "version": "2.3.0", "type": "framework",
         "purl": "pkg:pypi/flask@2.3.0", "licenses": ["BSD-3-Clause"]},
        {"name": "requests", "version": "2.28.0", "type": "library",
         "purl": "pkg:pypi/requests@2.28.0", "licenses": ["Apache-2.0"]},
        {"name": "numpy", "version": "1.21.0", "type": "library",
         "purl": "pkg:pypi/numpy@1.21.0", "licenses": ["BSD-3-Clause"]},
        {"name": "pandas", "version": "2.1.4", "type": "library",
         "purl": "pkg:pypi/pandas@2.1.4", "licenses": ["BSD-3-Clause"]},
        {"name": "pillow", "version": "9.5.0", "type": "library",
         "purl": "pkg:pypi/pillow@9.5.0", "licenses": ["MIT-CMU"]},
        {"name": "sqlalchemy", "version": "2.0.23", "type": "library",
         "purl": "pkg:pypi/sqlalchemy@2.0.23", "licenses": ["MIT"]},
        {"name": "pytorch", "version": "1.13.0", "type": "framework",
         "purl": "pkg:pypi/pytorch@1.13.0", "licenses": ["BSD-3-Clause"]},
        {"name": "tensorflow", "version": "2.11.0", "type": "framework",
         "purl": "pkg:pypi/tensorflow@2.11.0", "licenses": ["Apache-2.0"]},
        {"name": "transformers", "version": "4.35.0", "type": "library",
         "purl": "pkg:pypi/transformers@4.35.0", "licenses": ["Apache-2.0"]},
        {"name": "scikit-learn", "version": "0.23.2", "type": "library",
         "purl": "pkg:pypi/scikit-learn@0.23.2", "licenses": ["BSD-3-Clause"]},
        {"name": "onnx", "version": "1.14.0", "type": "library",
         "purl": "pkg:pypi/onnx@1.14.0", "licenses": ["Apache-2.0"]},
        {"name": "gunicorn", "version": "21.2.0", "type": "library",
         "purl": "pkg:pypi/gunicorn@21.2.0", "licenses": ["MIT"]},
        {"name": "celery", "version": "5.3.6", "type": "library",
         "purl": "pkg:pypi/celery@5.3.6", "licenses": ["BSD-3-Clause"]},
        {"name": "redis", "version": "5.0.1", "type": "library",
         "purl": "pkg:pypi/redis@5.0.1", "licenses": ["MIT"]},
        # A GPL-licensed package to trigger license risk
        {"name": "readline", "version": "8.2.0", "type": "library",
         "purl": "pkg:generic/readline@8.2.0", "licenses": ["GPL-3.0"]},
        # An AGPL package
        {"name": "mongo-connector", "version": "3.1.1", "type": "library",
         "purl": "pkg:pypi/mongo-connector@3.1.1", "licenses": ["AGPL-3.0"]},
    ]

    # Select a subset based on product_id
    count = rng.randint(15, len(base_components))
    selected = rng.sample(base_components, min(count, len(base_components)))

    # Enrich with missing fields
    for comp in selected:
        comp.setdefault("group", "")
        comp.setdefault("publisher", "")
        comp.setdefault("scope", "required")
        comp.setdefault("hashes", {})
        comp.setdefault("description", "")
        comp.setdefault("bom_ref", f"ref-{comp['name']}")
        comp.setdefault("cpe", "")
        comp.setdefault("model_card_url", None)
        comp["ecosystem"] = _ecosystem_from_purl(comp.get("purl", ""))

    return selected
