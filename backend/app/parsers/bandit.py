import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
CONFIDENCE_MAP = {"HIGH": 1.0, "MEDIUM": 0.7, "LOW": 0.4}


class BanditParser(BaseParser):
    name = "Bandit"
    scan_type = "SAST"
    description = "Bandit Python security linter"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        results = data.get("results", [])
        for item in results:
            cwe_val = None
            cwe_data = item.get("issue_cwe", {})
            if cwe_data and cwe_data.get("id"):
                cwe_val = cwe_data["id"]

            findings.append({
                "title": f"{item.get('test_id', '')}: {item.get('test_name', 'Unknown')}",
                "description": item.get("issue_text", ""),
                "severity": SEVERITY_MAP.get(item.get("issue_severity", "MEDIUM"), "medium"),
                "cwe": cwe_val,
                "file_path": item.get("filename", ""),
                "line_number": item.get("line_number"),
                "mitigation": item.get("more_info", ""),
                "unique_id": f"{item.get('test_id')}:{item.get('filename')}:{item.get('line_number')}",
            })

        return findings
