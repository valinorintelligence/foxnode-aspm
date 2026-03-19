import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


class SnykParser(BaseParser):
    name = "Snyk"
    scan_type = "SCA"
    description = "Snyk dependency vulnerability scanner"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        vulns = data.get("vulnerabilities", [])
        for vuln in vulns:
            findings.append({
                "title": vuln.get("title", "Unknown"),
                "description": vuln.get("description", ""),
                "severity": SEVERITY_MAP.get(vuln.get("severity", "medium"), "medium"),
                "cvss_score": vuln.get("cvssScore"),
                "cve": (vuln.get("identifiers", {}).get("CVE", [None]) or [None])[0],
                "cwe": self._extract_cwe(vuln),
                "component": vuln.get("packageName"),
                "component_version": vuln.get("version"),
                "mitigation": f"Upgrade to {vuln.get('upgradePath', ['N/A'])[-1] if vuln.get('upgradePath') else 'N/A'}",
                "references": vuln.get("url", ""),
                "unique_id": vuln.get("id"),
            })

        return findings

    def _extract_cwe(self, vuln: dict) -> int | None:
        cwes = vuln.get("identifiers", {}).get("CWE", [])
        if cwes:
            try:
                return int(str(cwes[0]).replace("CWE-", ""))
            except ValueError:
                pass
        return None
