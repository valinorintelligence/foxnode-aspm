import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


class TrivyParser(BaseParser):
    name = "Trivy"
    scan_type = "SCA"
    description = "Trivy container and filesystem vulnerability scanner"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        results = data if isinstance(data, list) else data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            for vuln in result.get("Vulnerabilities", []):
                findings.append({
                    "title": f"{vuln.get('VulnerabilityID', 'Unknown')} in {vuln.get('PkgName', 'unknown')}",
                    "description": vuln.get("Description", ""),
                    "severity": SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "info"),
                    "cvss_score": self._extract_cvss(vuln),
                    "cve": vuln.get("VulnerabilityID"),
                    "component": vuln.get("PkgName"),
                    "component_version": vuln.get("InstalledVersion"),
                    "file_path": target,
                    "mitigation": f"Update to {vuln.get('FixedVersion', 'N/A')}",
                    "references": "\n".join(vuln.get("References", [])[:5]),
                    "unique_id": vuln.get("VulnerabilityID"),
                })

            for misconfig in result.get("Misconfigurations", []):
                findings.append({
                    "title": misconfig.get("Title", "Misconfiguration"),
                    "description": misconfig.get("Description", ""),
                    "severity": SEVERITY_MAP.get(misconfig.get("Severity", "UNKNOWN"), "info"),
                    "file_path": target,
                    "mitigation": misconfig.get("Resolution", ""),
                    "unique_id": misconfig.get("ID"),
                })

        return findings

    def _extract_cvss(self, vuln: dict) -> float | None:
        cvss = vuln.get("CVSS", {})
        for source in cvss.values():
            if "V3Score" in source:
                return source["V3Score"]
        return None
