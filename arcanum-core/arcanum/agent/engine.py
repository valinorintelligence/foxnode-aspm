"""Core agent engine for Arcanum — drives the LLM tool-calling loop with
extended thinking, phase checkpoints, context compression, and self-evaluation."""

from __future__ import annotations

import json
import re
from typing import Any, AsyncGenerator

from .llm import OllamaClient
from .tools import NATIVE_TOOLS, ToolExecutor

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MODE_AUTOPILOT = "autopilot"
MODE_COPILOT = "copilot"
MODE_MANUAL = "manual"

PHASES = ["recon", "analysis", "exploit", "report"]

CHECKPOINT_EVAL_INTERVAL = 5     # Phase evaluation every N iterations
SELF_EVAL_INTERVAL = 10          # Self-evaluation every N iterations
CONTEXT_COMPRESS_INTERVAL = 15   # Context compression every N iterations
MAX_ITERATIONS = 50              # Safety limit per run


class AgentEngine:
    """Runs the agentic loop with extended thinking, phase tracking, and
    context compression (inspired by airecon's checkpoint system)."""

    def __init__(
        self,
        llm: OllamaClient,
        tool_executor: ToolExecutor,
        session: dict,
    ):
        self.llm = llm
        self.tool_executor = tool_executor
        self.session = session
        self.mode = session.get("mode", "manual") if isinstance(session, dict) else getattr(session, "mode", "manual")
        self.messages: list[dict] = []
        self.iteration = 0
        self.current_phase = "recon"
        self.completed_phases: list[str] = []
        self.findings_count = 0
        self.enable_thinking = True

    # -- Public API ---------------------------------------------------------

    async def run(self, user_input: str) -> AsyncGenerator[dict, None]:
        """Process user input through the agent loop.

        Yields event dicts with ``type``:
        thinking, tool_call, tool_result, response, finding, suggestion,
        phase_change, checkpoint, error.
        """
        system_prompt = await self._build_system_prompt()

        if not self.messages or self.messages[0].get("role") != "system":
            self.messages.insert(0, {"role": "system", "content": system_prompt})
        else:
            self.messages[0]["content"] = system_prompt

        self.messages.append({"role": "user", "content": user_input})

        # Deep recon autostart: bare domain triggers full pipeline
        if self.mode == MODE_AUTOPILOT and self._is_bare_domain(user_input):
            user_input = self._expand_to_full_recon(user_input)
            self.messages[-1]["content"] = user_input

        while self.iteration < MAX_ITERATIONS:
            self.iteration += 1

            # --- Checkpoint system ---
            if self.iteration % CHECKPOINT_EVAL_INTERVAL == 0:
                phase_event = await self._evaluate_phase()
                if phase_event:
                    yield phase_event

            if self.iteration % SELF_EVAL_INTERVAL == 0 and self.iteration > 0:
                eval_result = await self._self_evaluate()
                yield {"type": "checkpoint", "subtype": "self_eval", "iteration": self.iteration,
                       "phase": self.current_phase, "findings": self.findings_count,
                       "evaluation": eval_result}

            if self.iteration % CONTEXT_COMPRESS_INTERVAL == 0:
                compressed = self._compress_context()
                if compressed:
                    yield {"type": "checkpoint", "subtype": "context_compressed",
                           "iteration": self.iteration, "messages_before": compressed[0],
                           "messages_after": compressed[1]}

            try:
                yield {"type": "thinking", "content": f"Iteration {self.iteration} — Phase: {self.current_phase}"}

                response_msg = await self.llm.chat(
                    messages=self.messages,
                    tools=NATIVE_TOOLS,
                )

                # --- Extended thinking extraction ---
                content = response_msg.get("content", "")
                thinking, clean_content = self._extract_thinking(content)
                if thinking:
                    yield {"type": "thinking", "content": thinking}

                tool_calls: list[dict] = response_msg.get("tool_calls", [])

                # No tool calls — final text response
                if not tool_calls:
                    self.messages.append({"role": "assistant", "content": clean_content or content})
                    yield {"type": "response", "content": clean_content or content}
                    return

                self.messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})

                for tc in tool_calls:
                    fn = tc.get("function", {})
                    tool_name = fn.get("name", "")
                    arguments = fn.get("arguments", {})
                    if isinstance(arguments, str):
                        try:
                            arguments = json.loads(arguments)
                        except json.JSONDecodeError:
                            arguments = {"raw": arguments}

                    yield {"type": "tool_call", "tool": tool_name, "arguments": arguments,
                           "iteration": self.iteration}

                    # Mode-based gating
                    if self.mode == MODE_MANUAL:
                        yield {"type": "suggestion", "tool": tool_name, "arguments": arguments,
                               "risk": self._assess_risk(tool_name, arguments),
                               "message": "Manual mode: approve this tool call to proceed."}
                        continue

                    if self.mode == MODE_COPILOT:
                        yield {"type": "suggestion", "tool": tool_name, "arguments": arguments,
                               "risk": self._assess_risk(tool_name, arguments),
                               "message": "Copilot mode: confirm to execute."}

                    # Execute the tool
                    result = await self.tool_executor.execute_tool(tool_name, arguments)

                    tool_msg = self._format_tool_result(tool_name, result)
                    self.messages.append(tool_msg)

                    yield {"type": "tool_result", "tool": tool_name, "result": result,
                           "iteration": self.iteration}

                    # Surface findings
                    if tool_name == "create_finding" and result.get("success"):
                        self.findings_count += 1
                        output = result.get("output", {})
                        if output.get("status") != "duplicate":
                            yield {"type": "finding", "finding": output}

            except Exception as exc:
                yield {"type": "error", "error": str(exc), "iteration": self.iteration}
                return

        yield {"type": "error", "error": f"Max iterations ({MAX_ITERATIONS}) reached", "iteration": self.iteration}

    # -- Extended Thinking ---------------------------------------------------

    def _extract_thinking(self, content: str) -> tuple[str | None, str]:
        """Extract <think>...</think> blocks from LLM output."""
        match = re.search(r'<think>(.*?)</think>', content, re.DOTALL)
        if match:
            thinking = match.group(1).strip()
            clean = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
            return thinking, clean
        return None, content

    # -- Self-Evaluation -------------------------------------------------------

    async def _self_evaluate(self) -> dict:
        """Ask the LLM to evaluate its own progress and adjust strategy."""
        target = self.session.get("target", "unknown") if isinstance(self.session, dict) else "unknown"
        eval_prompt = (
            f"You are at iteration {self.iteration} of a security assessment against '{target}'. "
            f"Current phase: {self.current_phase}. Findings so far: {self.findings_count}.\n\n"
            "Briefly evaluate:\n"
            "1. Progress: Are you making adequate progress? (yes/no + reason)\n"
            "2. Coverage: What areas haven't been tested yet?\n"
            "3. Next steps: What are the 2-3 most important next actions?\n"
            "4. Should you move to the next phase? (yes/no)\n\n"
            "Reply in 3-5 sentences."
        )
        try:
            response = await self.llm.chat(
                messages=[
                    {"role": "system", "content": "You are a security assessment progress evaluator."},
                    {"role": "user", "content": eval_prompt},
                ],
            )
            content = response.get("content", "")
            _, clean = self._extract_thinking(content)
            return {"status": "ok", "evaluation": clean or content}
        except Exception as e:
            return {"status": "error", "evaluation": f"Self-eval failed: {e}"}

    # -- Phase Management ----------------------------------------------------

    async def _evaluate_phase(self) -> dict | None:
        """Evaluate whether we should transition to the next phase."""
        phase_idx = PHASES.index(self.current_phase) if self.current_phase in PHASES else 0

        # Simple heuristic: check tool calls in recent messages
        recent_tools = []
        for msg in self.messages[-10:]:
            for tc in msg.get("tool_calls", []):
                fn = tc.get("function", {})
                recent_tools.append(fn.get("name", ""))

        # Phase transition logic
        new_phase = self.current_phase
        if self.current_phase == "recon":
            recon_tools = {"execute"}  # subfinder, nmap etc run via execute
            if len(recent_tools) >= 3:
                new_phase = "analysis"
        elif self.current_phase == "analysis":
            if any(t == "create_finding" for t in recent_tools):
                new_phase = "exploit"
            elif len(recent_tools) >= 5:
                new_phase = "exploit"
        elif self.current_phase == "exploit":
            if self.findings_count >= 1:
                new_phase = "report"

        if new_phase != self.current_phase:
            old_phase = self.current_phase
            self.completed_phases.append(old_phase)
            self.current_phase = new_phase
            return {"type": "phase_change", "from": old_phase, "to": new_phase,
                    "completed_phases": self.completed_phases}
        return None

    # -- Context Compression -------------------------------------------------

    def _compress_context(self) -> tuple[int, int] | None:
        """Compress conversation history to avoid OOM.
        Keeps system prompt + last 20 messages, summarizes the rest."""
        if len(self.messages) <= 25:
            return None

        before = len(self.messages)
        system_msg = self.messages[0] if self.messages[0].get("role") == "system" else None
        recent = self.messages[-20:]

        # Build summary of compressed messages
        compressed_msgs = self.messages[1:-20] if system_msg else self.messages[:-20]
        tool_calls = []
        findings = []
        for msg in compressed_msgs:
            for tc in msg.get("tool_calls", []):
                fn = tc.get("function", {})
                tool_calls.append(f"{fn.get('name', '?')}({json.dumps(fn.get('arguments', {}), default=str)[:100]})")
            if msg.get("role") == "tool":
                content = msg.get("content", "")
                if "finding" in content.lower():
                    findings.append(content[:200])

        summary = {
            "role": "system",
            "content": f"[CONTEXT COMPRESSED] Previous {len(compressed_msgs)} messages summarized:\n"
                       f"- Tool calls executed: {', '.join(tool_calls[:20])}\n"
                       f"- Findings so far: {self.findings_count}\n"
                       f"- Current phase: {self.current_phase}\n"
                       f"- Completed phases: {', '.join(self.completed_phases)}\n"
        }

        self.messages = ([system_msg] if system_msg else []) + [summary] + recent
        return (before, len(self.messages))

    # -- Deep Recon Autostart -----------------------------------------------

    @staticmethod
    def _is_bare_domain(text: str) -> bool:
        """Check if input looks like just a bare domain."""
        text = text.strip().lower()
        # Match patterns like "example.com", "sub.example.com", "10.0.0.1"
        if re.match(r'^[a-z0-9]([a-z0-9\-]*\.)+[a-z]{2,}$', text):
            return True
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', text):
            return True
        return False

    @staticmethod
    def _expand_to_full_recon(target: str) -> str:
        return (
            f"Perform a comprehensive security assessment on {target}.\n\n"
            f"Execute the full reconnaissance pipeline:\n"
            f"1. Subdomain enumeration: subfinder -d {target} -all -o /workspace/output/subdomains.txt\n"
            f"2. DNS resolution: dnsx -l /workspace/output/subdomains.txt -a -resp -o /workspace/output/dns.txt\n"
            f"3. Live host detection: httpx -l /workspace/output/subdomains.txt -tech-detect -status-code -o /workspace/output/live.txt\n"
            f"4. Port scanning: nmap -sV -sC -iL /workspace/output/live.txt -oA /workspace/output/nmap\n"
            f"5. Vulnerability scanning: nuclei -l /workspace/output/live.txt -severity critical,high -o /workspace/output/vulns.txt\n"
            f"6. For any discovered web apps, test for SQLi, XSS, and other common vulns\n"
            f"7. Create findings for all confirmed vulnerabilities\n\n"
            f"Analyze all output at each step. Chain results between steps."
        )

    # -- Risk Assessment for Copilot ----------------------------------------

    @staticmethod
    def _assess_risk(tool_name: str, arguments: dict) -> str:
        """Assess risk level for copilot mode suggestions."""
        cmd = arguments.get("command", "").lower()

        high_risk = ["sqlmap", "metasploit", "hydra", "hashcat", "exploit", "pwncat", "sliver",
                      "bettercap", "mimikatz", "--risk 3", "--level 5"]
        medium_risk = ["nuclei", "ffuf", "feroxbuster", "dalfox", "wpscan", "nikto",
                       "nmap -sV", "nmap -sC", "arjun"]
        low_risk = ["subfinder", "dnsx", "httpx", "katana", "theHarvester", "whois",
                     "dig", "host", "curl", "wget", "sherlock", "holehe", "exiftool"]

        if any(r in cmd for r in high_risk):
            return "HIGH"
        if any(r in cmd for r in medium_risk):
            return "MEDIUM"
        if any(r in cmd for r in low_risk):
            return "LOW"

        # Default based on tool name
        if tool_name == "execute":
            return "MEDIUM"
        if tool_name in ("browser_action", "web_search", "read_file", "search_cve"):
            return "LOW"
        if tool_name == "create_finding":
            return "LOW"
        return "MEDIUM"

    # -- System Prompt -------------------------------------------------------

    async def _build_system_prompt(self) -> str:
        s = self.session
        name = s.get("name", "unknown") if isinstance(s, dict) else getattr(s, "name", "unknown")
        target = s.get("target", "*") if isinstance(s, dict) else getattr(s, "target", "*")
        scope = s.get("scope", "*") if isinstance(s, dict) else getattr(s, "scope", "*")

        tools_list = ", ".join(t["function"]["name"] for t in NATIVE_TOOLS)

        return f"""You are Arcanum, an autonomous security reconnaissance and penetration testing agent.
You perform authorized security assessments using professional tools in an isolated sandbox.

## Current Operation
- Session: {name}
- Target: {target}
- Mode: {self.mode}
- Scope: {scope}
- Current Phase: {self.current_phase} (Phases: {' → '.join(PHASES)})
- Completed Phases: {', '.join(self.completed_phases) or 'None'}
- Findings So Far: {self.findings_count}
- Iteration: {self.iteration}

## Available Tools
{tools_list}

## Rules
1. NEVER operate outside the defined scope.
2. Always verify targets are in-scope before running any tool.
3. Document EVERY finding with evidence and proof of concept.
4. Follow the principle of least privilege.
5. If you discover credentials or sensitive data, stash them and redact in outputs.
6. Only create findings for VERIFIED vulnerabilities with working PoC.

## Mode Behavior
- **autopilot**: Execute tools automatically. Chain recon workflows. Move through all phases.
- **copilot**: Suggest tool calls with risk assessment. Wait for operator confirmation.
- **manual**: Only execute tools when the operator explicitly requests them. Provide expert advice.

## Methodology (RECON → ANALYSIS → EXPLOIT → REPORT)
### Phase 1: Reconnaissance
- Enumerate subdomains (subfinder), resolve DNS (dnsx), probe HTTP (httpx)
- Port scan (nmap), crawl web (katana), fingerprint technologies

### Phase 2: Analysis
- Vulnerability scan (nuclei), directory brute-force (ffuf/feroxbuster)
- Parameter discovery (arjun), technology-specific checks (wpscan, testssl)
- Search CVE database for discovered versions

### Phase 3: Exploitation
- SQL injection (sqlmap), XSS (dalfox), SSTI, SSRF, IDOR testing
- Credential attacks if applicable (hydra, hashcat)
- Verify each vulnerability with a working PoC before creating a finding

### Phase 4: Reporting
- Create findings for all confirmed vulnerabilities with CVSS scores
- Stash important artifacts (credentials, tokens, hosts)
- Summarize the assessment

## Extended Thinking
You may use <think>...</think> blocks to reason through complex decisions before acting.
This helps you plan multi-step attack chains and evaluate risks.

Think step by step. Be thorough. Chain tool results. Create findings only for confirmed vulns."""

    @staticmethod
    def _format_tool_result(name: str, result: dict) -> dict:
        content = json.dumps(result, default=str)
        # Truncate very long results
        if len(content) > 30000:
            content = content[:30000] + "\n...[truncated]"
        return {"role": "tool", "name": name, "content": content}
