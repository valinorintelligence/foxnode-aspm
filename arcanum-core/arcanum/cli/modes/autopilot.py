"""Autopilot mode - full autonomous operation."""
from rich.console import Console

console = Console()


class AutopilotRunner:
    """Runs full autonomous security assessment."""

    PHASES = [
        ("recon", "Reconnaissance", [
            "subfinder -d {target} -all -o workspace/output/subdomains.txt",
            "dnsx -l workspace/output/subdomains.txt -a -resp -o workspace/output/dns.txt",
            "httpx -l workspace/output/subdomains.txt -tech-detect -status-code -o workspace/output/live_hosts.txt",
        ]),
        ("scanning", "Port Scanning", [
            "nmap -sV -sC -iL workspace/output/live_hosts.txt -oA workspace/output/nmap_scan",
        ]),
        ("vuln_scan", "Vulnerability Scanning", [
            "nuclei -l workspace/output/live_hosts.txt -severity critical,high -o workspace/output/nuclei_results.txt",
        ]),
        ("exploitation", "Exploitation", [
            "sqlmap -m workspace/output/urls_with_params.txt --batch --level 3 --risk 2",
            "dalfox file workspace/output/urls_with_params.txt --silence",
        ]),
        ("reporting", "Report Generation", []),
    ]

    def __init__(self, engine, target: str):
        self.engine = engine
        self.target = target
        self.completed_phases = []

    async def run(self):
        """Run full autopilot assessment."""
        yield {"type": "autopilot_start", "target": self.target, "phases": len(self.PHASES)}

        prompt = f"""You are running a full autonomous security assessment on {self.target}.

Execute a comprehensive penetration test following this methodology:
1. Subdomain enumeration and DNS resolution
2. Live host detection and technology fingerprinting
3. Port scanning and service detection
4. Vulnerability scanning with nuclei
5. Targeted exploitation of discovered vulnerabilities
6. Generate a complete findings report

Start with reconnaissance. Use the execute tool to run commands in the sandbox.
Target: {self.target}
"""
        async for event in self.engine.run(prompt):
            yield event

        yield {"type": "autopilot_complete", "target": self.target}
