import json
from app.parsers.registry import BaseParser

LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


class SarifParser(BaseParser):
    name = "SARIF"
    scan_type = "SAST"
    description = "SARIF (Static Analysis Results Interchange Format) universal parser"

    def parse(self, content: bytes) -> list[dict]:
        data = json.loads(content)
        findings = []

        for run in data.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")

            # Build a rule lookup from tool.driver.rules
            rules_lookup = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules_lookup[rule.get("id", "")] = rule

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule_info = rules_lookup.get(rule_id, {})

                # Severity: prefer result level, fall back to rule defaultConfiguration
                level = result.get("level")
                if not level:
                    level = rule_info.get("defaultConfiguration", {}).get("level", "warning")
                severity = LEVEL_MAP.get(level, "medium")

                # Message
                message = result.get("message", {}).get("text", "")

                # Description from rule
                description = rule_info.get("fullDescription", rule_info.get("shortDescription", {}))
                if isinstance(description, dict):
                    description = description.get("text", "")

                # Location
                file_path = ""
                line_number = None
                locations = result.get("locations", [])
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {})
                    file_path = artifact.get("uri", "")
                    region = phys.get("region", {})
                    line_number = region.get("startLine")

                # Help / mitigation from rule
                help_info = rule_info.get("help", {})
                mitigation = help_info.get("text", "") if isinstance(help_info, dict) else str(help_info)

                # References from rule helpUri
                help_uri = rule_info.get("helpUri", "")

                findings.append({
                    "title": f"[{tool_name}] {rule_id}: {message}" if rule_id else f"[{tool_name}] {message}",
                    "description": description or message,
                    "severity": severity,
                    "file_path": file_path,
                    "line_number": line_number,
                    "mitigation": mitigation,
                    "references": help_uri,
                    "unique_id": f"sarif-{tool_name}-{rule_id}-{file_path}-{line_number}",
                })

        return findings
