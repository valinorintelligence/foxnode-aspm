import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class DependencyCheckParser(BaseParser):
    name = "DependencyCheck"
    scan_type = "SCA"
    description = "OWASP Dependency-Check vulnerability scanner"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            vulns = dep.get("vulnerabilities", [])
            if not vulns:
                continue

            dep_name = dep.get("fileName", dep.get("filePath", "unknown"))

            for vuln in vulns:
                severity_raw = vuln.get("severity", "MEDIUM").upper()
                severity = SEVERITY_MAP.get(severity_raw, "medium")

                # Extract CVSS score from cvssv3 or cvssv2
                cvss_score = None
                cvssv3 = vuln.get("cvssv3")
                cvssv2 = vuln.get("cvssv2")
                if cvssv3:
                    cvss_score = cvssv3.get("baseScore")
                elif cvssv2:
                    cvss_score = cvssv2.get("score")

                # Collect CVE references
                cve_name = vuln.get("name", "")
                refs = vuln.get("references", [])
                ref_urls = [r.get("url", "") for r in refs if r.get("url")]

                # CWEs
                cwes = vuln.get("cwes", [])
                cwe_val = None
                if cwes:
                    try:
                        cwe_val = int(str(cwes[0]).replace("CWE-", ""))
                    except (ValueError, IndexError):
                        pass

                findings.append({
                    "title": f"{cve_name} in {dep_name}",
                    "description": vuln.get("description", ""),
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cve": cve_name if cve_name.startswith("CVE-") else None,
                    "cwe": cwe_val,
                    "component": dep_name,
                    "component_version": dep.get("version"),
                    "file_path": dep.get("filePath", ""),
                    "mitigation": "",
                    "references": "\n".join(ref_urls[:5]),
                    "unique_id": f"depcheck-{cve_name}-{dep_name}",
                })

        return findings
