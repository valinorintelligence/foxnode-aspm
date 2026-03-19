import json
from app.parsers.registry import BaseParser

RISK_MAP = {"3": "high", "2": "medium", "1": "low", "0": "info"}


class ZapParser(BaseParser):
    name = "ZAP"
    scan_type = "DAST"
    description = "OWASP ZAP dynamic security scanner"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        # Handle both ZAP JSON and traditional report formats
        sites = data.get("site", [])
        if not isinstance(sites, list):
            sites = [sites]

        for site in sites:
            alerts = site.get("alerts", [])
            for alert in alerts:
                cwe_val = None
                if alert.get("cweid") and str(alert["cweid"]) != "-1":
                    try:
                        cwe_val = int(alert["cweid"])
                    except ValueError:
                        pass

                instances = alert.get("instances", [])
                uri = instances[0].get("uri", "") if instances else ""

                findings.append({
                    "title": alert.get("name", alert.get("alert", "Unknown")),
                    "description": alert.get("desc", ""),
                    "severity": RISK_MAP.get(str(alert.get("riskcode", "1")), "medium"),
                    "cwe": cwe_val,
                    "file_path": uri,
                    "mitigation": alert.get("solution", ""),
                    "references": alert.get("reference", ""),
                    "unique_id": f"zap-{alert.get('pluginid', '')}-{alert.get('name', '')}",
                })

        return findings
