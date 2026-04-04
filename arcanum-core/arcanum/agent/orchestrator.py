"""Workflow orchestrator for Arcanum autopilot mode."""

from __future__ import annotations

from typing import Any, AsyncGenerator

from .engine import AgentEngine


# ---------------------------------------------------------------------------
# Predefined multi-tool workflows
# ---------------------------------------------------------------------------

WORKFLOWS: dict[str, list[dict]] = {
    "full_recon": [
        {
            "tool": "execute",
            "description": "Subdomain enumeration with subfinder",
            "command": "subfinder -d {target} -silent -o /tmp/subs.txt",
        },
        {
            "tool": "execute",
            "description": "DNS resolution with dnsx",
            "command": "dnsx -l /tmp/subs.txt -silent -o /tmp/resolved.txt",
        },
        {
            "tool": "execute",
            "description": "HTTP probing with httpx",
            "command": "httpx -l /tmp/resolved.txt -silent -o /tmp/alive.txt",
        },
        {
            "tool": "execute",
            "description": "Port scanning with nmap",
            "command": "nmap -iL /tmp/resolved.txt -T4 -oA /tmp/nmap_scan",
        },
        {
            "tool": "execute",
            "description": "Vulnerability scanning with nuclei",
            "command": "nuclei -l /tmp/alive.txt -severity critical,high,medium -o /tmp/nuclei_results.txt",
        },
    ],
    "web_scan": [
        {
            "tool": "execute",
            "description": "HTTP probing with httpx",
            "command": "httpx -u {target} -silent -tech-detect -status-code -o /tmp/httpx_out.txt",
        },
        {
            "tool": "execute",
            "description": "Web crawling with katana",
            "command": "katana -u {target} -silent -o /tmp/katana_urls.txt",
        },
        {
            "tool": "execute",
            "description": "Vulnerability scanning with nuclei",
            "command": "nuclei -u {target} -severity critical,high,medium -o /tmp/nuclei_web.txt",
        },
        {
            "tool": "execute",
            "description": "SQL injection testing with sqlmap",
            "command": "sqlmap -u {target} --batch --crawl=2 --output-dir=/tmp/sqlmap_out",
        },
        {
            "tool": "execute",
            "description": "XSS scanning with dalfox",
            "command": "dalfox url {target} --silence --output /tmp/dalfox_out.txt",
        },
    ],
    "network_scan": [
        {
            "tool": "execute",
            "description": "Port and service scanning with nmap",
            "command": "nmap -sV -sC {target} -oA /tmp/nmap_network",
        },
        {
            "tool": "execute",
            "description": "Network service enumeration with netexec",
            "command": "netexec smb {target} --shares",
        },
        {
            "tool": "execute",
            "description": "SNMP enumeration with snmpwalk",
            "command": "snmpwalk -v2c -c public {target}",
        },
    ],
}


class Orchestrator:
    """Manages multi-tool workflows for autopilot mode."""

    def __init__(self) -> None:
        self.workflows = WORKFLOWS

    async def run_workflow(
        self,
        workflow_name: str,
        target: str,
        engine: AgentEngine,
    ) -> AsyncGenerator[dict, None]:
        """Execute a predefined workflow step-by-step.

        Yields event dicts compatible with ``AgentEngine.run`` events plus
        workflow-specific ``workflow_step`` and ``workflow_complete`` events.
        """
        steps = self.workflows.get(workflow_name)
        if steps is None:
            yield {
                "type": "error",
                "error": f"Unknown workflow: {workflow_name}. "
                f"Available: {', '.join(self.workflows.keys())}",
            }
            return

        total = len(steps)

        yield {
            "type": "workflow_start",
            "workflow": workflow_name,
            "target": target,
            "total_steps": total,
        }

        for idx, step in enumerate(steps, start=1):
            command = step["command"].replace("{target}", target)

            yield {
                "type": "workflow_step",
                "step": idx,
                "total": total,
                "description": step["description"],
                "command": command,
            }

            # Drive execution through the agent engine so the LLM can
            # interpret results, chain decisions, and create findings.
            prompt = (
                f"Execute step {idx}/{total} of the {workflow_name} workflow.\n"
                f"Description: {step['description']}\n"
                f"Run this command: {command}\n\n"
                f"Analyze the output. If you find anything notable, "
                f"create a finding or stash the artifact."
            )

            async for event in engine.run(prompt):
                yield event

        yield {
            "type": "workflow_complete",
            "workflow": workflow_name,
            "target": target,
            "total_steps": total,
        }

    def list_workflows(self) -> list[dict[str, Any]]:
        """Return metadata for all available workflows."""
        result = []
        for name, steps in self.workflows.items():
            result.append(
                {
                    "name": name,
                    "steps": len(steps),
                    "tools": [s["description"] for s in steps],
                }
            )
        return result
