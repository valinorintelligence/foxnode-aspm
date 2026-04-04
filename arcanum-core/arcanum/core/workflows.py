"""YAML-based reusable workflow templates."""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class WorkflowStep:
    name: str
    tool: str
    command: str
    description: str = ""
    risk: str = "low"
    timeout: int = 300
    depends_on: list[str] = field(default_factory=list)
    on_success: str | None = None
    on_failure: str | None = None


@dataclass
class WorkflowTemplate:
    name: str
    description: str
    author: str = "arcanum"
    version: str = "1.0"
    category: str = "general"
    tags: list[str] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    steps: list[WorkflowStep] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in workflow templates
# ---------------------------------------------------------------------------

BUILTIN_WORKFLOWS = {
    "full_recon": {
        "name": "full_recon",
        "description": "Comprehensive reconnaissance pipeline for a target domain",
        "category": "recon",
        "tags": ["subdomain", "dns", "ports", "vulns"],
        "variables": {"target": "example.com"},
        "steps": [
            {"name": "subdomain_enum", "tool": "execute", "command": "subfinder -d {target} -all -o /workspace/output/subdomains.txt", "description": "Enumerate subdomains", "risk": "low"},
            {"name": "dns_resolve", "tool": "execute", "command": "dnsx -l /workspace/output/subdomains.txt -a -resp -o /workspace/output/dns.txt", "description": "Resolve DNS records", "risk": "low", "depends_on": ["subdomain_enum"]},
            {"name": "live_hosts", "tool": "execute", "command": "httpx -l /workspace/output/subdomains.txt -tech-detect -status-code -o /workspace/output/live.txt", "description": "Probe live HTTP hosts", "risk": "low", "depends_on": ["subdomain_enum"]},
            {"name": "port_scan", "tool": "execute", "command": "nmap -sV -sC -iL /workspace/output/live.txt -oA /workspace/output/nmap", "description": "Scan ports and services", "risk": "low", "depends_on": ["live_hosts"], "timeout": 600},
            {"name": "vuln_scan", "tool": "execute", "command": "nuclei -l /workspace/output/live.txt -severity critical,high -o /workspace/output/vulns.txt", "description": "Template-based vulnerability scan", "risk": "medium", "depends_on": ["live_hosts"], "timeout": 600},
        ],
    },
    "web_assessment": {
        "name": "web_assessment",
        "description": "Full web application security assessment",
        "category": "web",
        "tags": ["web", "sqli", "xss", "dirs"],
        "variables": {"target": "https://example.com"},
        "steps": [
            {"name": "tech_detect", "tool": "execute", "command": "httpx -u {target} -tech-detect -json -o /workspace/output/tech.json", "description": "Technology fingerprinting", "risk": "low"},
            {"name": "crawl", "tool": "execute", "command": "katana -u {target} -depth 3 -o /workspace/output/urls.txt", "description": "Deep web crawling", "risk": "low"},
            {"name": "dir_scan", "tool": "execute", "command": "feroxbuster -u {target} -w /opt/seclists/Discovery/Web-Content/raft-medium-directories.txt -o /workspace/output/dirs.txt", "description": "Directory brute-forcing", "risk": "medium"},
            {"name": "nuclei_scan", "tool": "execute", "command": "nuclei -u {target} -severity critical,high,medium -o /workspace/output/nuclei.txt", "description": "Vulnerability scanning", "risk": "medium"},
            {"name": "sqli_test", "tool": "execute", "command": "sqlmap -u {target} --batch --crawl=2 --level 3 --risk 2 --output-dir=/workspace/output/sqlmap", "description": "SQL injection testing", "risk": "high", "depends_on": ["crawl"]},
            {"name": "xss_test", "tool": "execute", "command": "dalfox file /workspace/output/urls.txt --silence --output /workspace/output/xss.txt", "description": "XSS scanning", "risk": "medium", "depends_on": ["crawl"]},
            {"name": "param_discovery", "tool": "execute", "command": "arjun -u {target} -o /workspace/output/params.json", "description": "Hidden parameter discovery", "risk": "medium"},
        ],
    },
    "network_pentest": {
        "name": "network_pentest",
        "description": "Internal network penetration test",
        "category": "network",
        "tags": ["network", "smb", "snmp", "nmap"],
        "variables": {"target": "10.0.0.0/24"},
        "steps": [
            {"name": "host_discovery", "tool": "execute", "command": "nmap -sn {target} -oG /workspace/output/hosts.txt", "description": "Network host discovery", "risk": "low"},
            {"name": "port_scan", "tool": "execute", "command": "nmap -sV -sC -iL /workspace/output/hosts.txt -oA /workspace/output/nmap_net", "description": "Port and service scan", "risk": "low", "depends_on": ["host_discovery"], "timeout": 900},
            {"name": "smb_enum", "tool": "execute", "command": "netexec smb {target} --shares", "description": "SMB share enumeration", "risk": "medium"},
            {"name": "snmp_enum", "tool": "execute", "command": "snmpwalk -v2c -c public {target}", "description": "SNMP enumeration", "risk": "low"},
        ],
    },
    "bug_bounty": {
        "name": "bug_bounty",
        "description": "Bug bounty hunting methodology",
        "category": "web",
        "tags": ["bugbounty", "recon", "web", "automation"],
        "variables": {"target": "example.com"},
        "steps": [
            {"name": "subdomain_enum", "tool": "execute", "command": "subfinder -d {target} -all -o /workspace/output/subs.txt", "description": "Subdomain enumeration", "risk": "low"},
            {"name": "live_filter", "tool": "execute", "command": "httpx -l /workspace/output/subs.txt -tech-detect -status-code -fc 404 -o /workspace/output/live.txt", "description": "Filter live hosts", "risk": "low"},
            {"name": "screenshot", "tool": "execute", "command": "gowitness file -f /workspace/output/live.txt -P /workspace/output/screenshots/", "description": "Screenshot all live hosts", "risk": "low"},
            {"name": "nuclei_critical", "tool": "execute", "command": "nuclei -l /workspace/output/live.txt -severity critical,high -o /workspace/output/critical_vulns.txt", "description": "Scan for critical vulns only", "risk": "medium"},
            {"name": "secret_scan", "tool": "execute", "command": "katana -u {target} -d 3 -jc | grep -iE 'api|key|token|secret|password' > /workspace/output/secrets.txt", "description": "Hunt for exposed secrets", "risk": "low"},
        ],
    },
    "api_security": {
        "name": "api_security",
        "description": "REST/GraphQL API security assessment",
        "category": "web",
        "tags": ["api", "graphql", "jwt", "fuzz"],
        "variables": {"target": "https://api.example.com"},
        "steps": [
            {"name": "api_discover", "tool": "execute", "command": "ffuf -u {target}/FUZZ -w /opt/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,401,403 -o /workspace/output/api_endpoints.json -of json", "description": "API endpoint discovery", "risk": "medium"},
            {"name": "graphql_test", "tool": "execute", "command": "graphqlmap -u {target}/graphql --method POST", "description": "GraphQL introspection and testing", "risk": "medium"},
            {"name": "nuclei_api", "tool": "execute", "command": "nuclei -u {target} -t exposures/ -t misconfiguration/ -o /workspace/output/api_vulns.txt", "description": "API-specific vulnerability scan", "risk": "medium"},
        ],
    },
}


class WorkflowManager:
    """Load, save, and execute YAML workflow templates."""

    def __init__(self, workflows_dir: Path = None):
        self.workflows_dir = workflows_dir
        self._templates: dict[str, dict] = dict(BUILTIN_WORKFLOWS)
        if workflows_dir:
            self._load_custom_workflows()

    def _load_custom_workflows(self):
        if not self.workflows_dir or not self.workflows_dir.exists():
            return
        for yaml_file in self.workflows_dir.glob("*.yml"):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if data and "name" in data:
                    self._templates[data["name"]] = data
            except Exception:
                pass
        for yaml_file in self.workflows_dir.glob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if data and "name" in data:
                    self._templates[data["name"]] = data
            except Exception:
                pass

    def get(self, name: str) -> dict | None:
        return self._templates.get(name)

    def list_all(self) -> list[dict]:
        return [
            {"name": t["name"], "description": t.get("description", ""),
             "category": t.get("category", ""), "steps": len(t.get("steps", []))}
            for t in self._templates.values()
        ]

    def save(self, template: dict, filename: str = None):
        if not self.workflows_dir:
            return
        self.workflows_dir.mkdir(parents=True, exist_ok=True)
        fname = filename or f"{template['name']}.yml"
        with open(self.workflows_dir / fname, "w") as f:
            yaml.dump(template, f, default_flow_style=False)
        self._templates[template["name"]] = template

    def resolve_steps(self, name: str, target: str) -> list[dict] | None:
        template = self.get(name)
        if not template:
            return None
        steps = []
        for step in template.get("steps", []):
            resolved = dict(step)
            resolved["command"] = resolved["command"].replace("{target}", target)
            steps.append(resolved)
        return steps
