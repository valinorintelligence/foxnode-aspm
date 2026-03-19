import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {
    "BLOCKER": "critical",
    "CRITICAL": "critical",
    "MAJOR": "high",
    "MINOR": "medium",
    "INFO": "info",
}


class SonarQubeParser(BaseParser):
    name = "SonarQube"
    scan_type = "SAST"
    description = "SonarQube static analysis scanner"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        issues = data.get("issues", [])
        for issue in issues:
            severity = SEVERITY_MAP.get(issue.get("severity", "INFO"), "info")

            component = issue.get("component", "")
            # SonarQube component format: project:path/to/file
            file_path = component.split(":", 1)[-1] if ":" in component else component

            text_range = issue.get("textRange", {})
            line = text_range.get("startLine", issue.get("line"))

            findings.append({
                "title": f"{issue.get('rule', 'Unknown')}: {issue.get('message', '')}",
                "description": issue.get("message", ""),
                "severity": severity,
                "file_path": file_path,
                "line_number": line,
                "component": component,
                "mitigation": "",
                "unique_id": issue.get("key", f"sonar-{issue.get('rule', '')}-{component}-{line}"),
            })

        return findings
