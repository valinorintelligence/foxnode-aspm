import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


class ProwlerParser(BaseParser):
    name = "Prowler"
    scan_type = "Cloud Security"
    description = "Prowler AWS/Azure/GCP cloud security scanner"

    def parse(self, content: bytes) -> list[dict]:
        findings = []

        # Prowler outputs JSONL (one JSON object per line)
        for line in content.decode("utf-8", errors="ignore").strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Only include failed checks
            status = item.get("Status", item.get("status", ""))
            if status.upper() == "PASS":
                continue

            severity = SEVERITY_MAP.get(
                item.get("Severity", item.get("severity", "medium")).lower(),
                "medium",
            )

            remediation = item.get("Remediation", item.get("remediation", {}))
            if isinstance(remediation, dict):
                remediation_text = remediation.get("Recommendation", {}).get("Text", "")
                remediation_url = remediation.get("Recommendation", {}).get("Url", "")
                remediation_str = f"{remediation_text}\n{remediation_url}".strip()
            else:
                remediation_str = str(remediation)

            resource_id = item.get("ResourceId", item.get("resource_id", ""))
            check_title = item.get("CheckTitle", item.get("check_title", ""))

            findings.append({
                "title": check_title or item.get("CheckID", "Unknown"),
                "description": item.get("StatusExtended", item.get("status_extended", "")),
                "severity": severity,
                "file_path": resource_id,
                "component": resource_id,
                "mitigation": remediation_str,
                "unique_id": f"prowler-{item.get('CheckID', '')}-{resource_id}",
            })

        return findings
