import json
from app.parsers.registry import BaseParser


class GitleaksParser(BaseParser):
    name = "Gitleaks"
    scan_type = "Secret Detection"
    description = "Gitleaks secret detection scanner"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        items = data if isinstance(data, list) else [data]
        for item in items:
            findings.append({
                "title": f"Secret Detected: {item.get('RuleID', item.get('ruleID', 'unknown'))}",
                "description": f"Secret found matching rule: {item.get('Description', item.get('description', ''))}",
                "severity": "high",
                "file_path": item.get("File", item.get("file", "")),
                "line_number": item.get("StartLine", item.get("startLine")),
                "mitigation": "Rotate the exposed secret and remove it from the codebase",
                "unique_id": item.get("Fingerprint", item.get("fingerprint")),
            })

        return findings
