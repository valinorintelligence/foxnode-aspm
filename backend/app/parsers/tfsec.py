import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class TfsecParser(BaseParser):
    name = "tfsec"
    scan_type = "IaC"
    description = "tfsec Terraform security scanner"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        results = data.get("results", [])
        if results is None:
            results = []

        for result in results:
            severity = SEVERITY_MAP.get(
                result.get("severity", "MEDIUM").upper(), "medium"
            )

            location = result.get("location", {})
            filename = location.get("filename", "")
            start_line = location.get("start_line")

            rule_id = result.get("rule_id", result.get("long_id", ""))
            rule_desc = result.get("rule_description", result.get("description", ""))

            references = result.get("links", [])
            ref_str = "\n".join(references[:5]) if references else ""

            findings.append({
                "title": f"{rule_id}: {rule_desc}",
                "description": result.get("description", rule_desc),
                "severity": severity,
                "file_path": filename,
                "line_number": start_line,
                "mitigation": result.get("resolution", ""),
                "references": ref_str,
                "unique_id": f"tfsec-{rule_id}-{filename}-{start_line}",
            })

        return findings
