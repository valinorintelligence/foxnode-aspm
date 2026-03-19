import csv
import io
import json
from app.parsers.registry import BaseParser

SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical", "4": "critical",
    "high": "high", "3": "high",
    "medium": "medium", "med": "medium", "moderate": "medium", "2": "medium",
    "low": "low", "1": "low",
    "info": "info", "informational": "info", "none": "info", "0": "info",
}


class GenericParser(BaseParser):
    name = "Generic"
    scan_type = "Generic"
    description = "Generic CSV/JSON import format for any scanner"

    def parse(self, content: bytes) -> list[dict]:
        text = content.decode("utf-8", errors="ignore")

        # Try JSON first
        try:
            data = json.loads(text)
            return self._parse_json(data)
        except json.JSONDecodeError:
            pass

        # Try CSV
        try:
            return self._parse_csv(text)
        except Exception:
            pass

        return []

    def _parse_json(self, data) -> list[dict]:
        items = data if isinstance(data, list) else data.get("findings", data.get("results", []))
        findings = []
        for item in items:
            findings.append({
                "title": item.get("title", item.get("name", "Unknown")),
                "description": item.get("description", item.get("detail", "")),
                "severity": SEVERITY_ALIASES.get(
                    str(item.get("severity", "medium")).lower(), "medium"
                ),
                "cvss_score": item.get("cvss_score", item.get("cvss")),
                "cve": item.get("cve", item.get("cve_id")),
                "cwe": item.get("cwe", item.get("cwe_id")),
                "file_path": item.get("file_path", item.get("file", item.get("location", ""))),
                "line_number": item.get("line_number", item.get("line")),
                "component": item.get("component", item.get("package")),
                "component_version": item.get("component_version", item.get("version")),
                "mitigation": item.get("mitigation", item.get("remediation", item.get("fix", ""))),
                "unique_id": item.get("id", item.get("unique_id")),
            })
        return findings

    def _parse_csv(self, text: str) -> list[dict]:
        reader = csv.DictReader(io.StringIO(text))
        findings = []
        for row in reader:
            # Normalize column names to lowercase
            row = {k.lower().strip(): v for k, v in row.items()}
            findings.append({
                "title": row.get("title", row.get("name", "Unknown")),
                "description": row.get("description", ""),
                "severity": SEVERITY_ALIASES.get(
                    row.get("severity", "medium").lower(), "medium"
                ),
                "cve": row.get("cve", row.get("cve_id")),
                "file_path": row.get("file_path", row.get("file", row.get("location", ""))),
                "component": row.get("component", row.get("package")),
                "mitigation": row.get("mitigation", row.get("fix", "")),
            })
        return findings
