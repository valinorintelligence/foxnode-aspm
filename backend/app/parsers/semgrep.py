import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


class SemgrepParser(BaseParser):
    name = "Semgrep"
    scan_type = "SAST"
    description = "Semgrep static analysis findings"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        results = data.get("results", data) if isinstance(data, dict) else data
        for item in results:
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})
            severity_str = extra.get("severity", "WARNING")

            findings.append({
                "title": item.get("check_id", "Unknown rule"),
                "description": extra.get("message", ""),
                "severity": SEVERITY_MAP.get(severity_str, "medium"),
                "cwe": self._extract_cwe(metadata),
                "file_path": item.get("path", ""),
                "line_number": item.get("start", {}).get("line"),
                "mitigation": extra.get("fix", ""),
                "references": metadata.get("source", ""),
                "unique_id": item.get("check_id"),
            })

        return findings

    def _extract_cwe(self, metadata: dict) -> int | None:
        cwes = metadata.get("cwe", [])
        if isinstance(cwes, list) and cwes:
            try:
                return int(str(cwes[0]).split("-")[-1])
            except (ValueError, IndexError):
                pass
        return None
