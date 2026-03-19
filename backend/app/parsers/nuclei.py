import json
from app.parsers.registry import BaseParser

SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


class NucleiParser(BaseParser):
    name = "Nuclei"
    scan_type = "DAST"
    description = "Nuclei vulnerability scanner"

    def parse(self, content: bytes) -> list[dict]:
        findings = []

        # Nuclei outputs JSONL (one JSON object per line)
        for line in content.decode("utf-8", errors="ignore").strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = item.get("info", {})
            severity = SEVERITY_MAP.get(info.get("severity", "info"), "info")

            cve = None
            classification = info.get("classification", {})
            cve_ids = classification.get("cve-id", [])
            if cve_ids:
                cve = cve_ids[0] if isinstance(cve_ids, list) else cve_ids

            cwe_val = None
            cwe_ids = classification.get("cwe-id", [])
            if cwe_ids:
                try:
                    cwe_str = cwe_ids[0] if isinstance(cwe_ids, list) else cwe_ids
                    cwe_val = int(str(cwe_str).replace("CWE-", ""))
                except (ValueError, IndexError):
                    pass

            findings.append({
                "title": info.get("name", item.get("template-id", "Unknown")),
                "description": info.get("description", ""),
                "severity": severity,
                "cvss_score": classification.get("cvss-score"),
                "cve": cve,
                "cwe": cwe_val,
                "file_path": item.get("matched-at", item.get("host", "")),
                "mitigation": info.get("remediation", ""),
                "references": "\n".join(info.get("reference", [])[:5]) if info.get("reference") else "",
                "unique_id": f"nuclei-{item.get('template-id', '')}-{item.get('matched-at', '')}",
            })

        return findings
