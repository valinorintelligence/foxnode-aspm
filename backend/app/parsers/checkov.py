import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


class CheckovParser(BaseParser):
    name = "Checkov"
    scan_type = "IaC"
    description = "Checkov Infrastructure-as-Code security scanner"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        # Checkov wraps results; handle both single-framework and multi-framework output
        if isinstance(data, list):
            checks_list = []
            for entry in data:
                checks_list.extend(
                    entry.get("results", {}).get("failed_checks", [])
                )
        else:
            checks_list = data.get("results", {}).get("failed_checks", [])

        for check in checks_list:
            severity = SEVERITY_MAP.get(
                check.get("severity", check.get("check_type", "UNKNOWN")).upper(),
                "medium",
            )

            guideline = check.get("guideline", "")
            references = guideline if isinstance(guideline, str) else ""

            findings.append({
                "title": f"{check.get('check_id', 'Unknown')}: {check.get('check_result', {}).get('result', 'FAILED')}",
                "description": check.get("check_id", ""),
                "severity": severity,
                "file_path": check.get("file_path", ""),
                "line_number": check.get("file_line_range", [None])[0],
                "component": check.get("resource", ""),
                "mitigation": guideline,
                "references": references,
                "unique_id": f"checkov-{check.get('check_id', '')}-{check.get('resource', '')}",
            })

        return findings
