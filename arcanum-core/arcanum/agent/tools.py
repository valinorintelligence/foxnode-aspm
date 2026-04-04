"""Native tool definitions and executor for the Arcanum agent."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Tool definitions (OpenAI-style tool-calling format)
# ---------------------------------------------------------------------------

NATIVE_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "execute",
            "description": "Run a shell command inside the Docker sandbox environment. Use this for all security tools (nmap, subfinder, nuclei, sqlmap, etc).",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Maximum execution time in seconds (default 300, max 900).",
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_action",
            "description": "Perform a headless browser automation action for JavaScript rendering, form interaction, and authentication workflows.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["navigate", "click", "type", "screenshot", "get_text", "get_source"],
                        "description": "The browser action to perform.",
                    },
                    "url": {"type": "string", "description": "URL to navigate to (for navigate action)."},
                    "selector": {"type": "string", "description": "CSS selector for the target element."},
                    "text": {"type": "string", "description": "Text to type (for type action)."},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for CVEs, bypass techniques, exploits, and security advisories.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query."},
                    "num_results": {"type": "integer", "description": "Number of results to return.", "default": 5},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_file",
            "description": "Write a file to the operation workspace (exploit scripts, wordlists, configs).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path within the workspace."},
                    "content": {"type": "string", "description": "File content to write."},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from the operation workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path within the workspace."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_finding",
            "description": "Create a verified vulnerability finding with evidence and proof of concept. Only use when you have confirmed a vulnerability.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short title of the vulnerability."},
                    "type": {"type": "string", "description": "Vulnerability type (sqli, xss, rce, ssrf, idor, lfi, xxe, csrf, misconfiguration)."},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "cvss_score": {"type": "number", "description": "CVSS v3.1 base score (0.0 - 10.0)."},
                    "affected": {"type": "object", "description": "Affected asset: {url, parameter, method, component}."},
                    "evidence": {"type": "object", "description": "Evidence: {request, response, screenshot}."},
                    "poc": {"type": "object", "description": "Proof of concept: {command, script, steps}."},
                    "remediation": {"type": "string", "description": "Recommended remediation steps."},
                },
                "required": ["title", "type", "severity", "cvss_score", "affected", "evidence", "poc", "remediation"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_cve",
            "description": "Search the local CVE knowledge base for known vulnerabilities by keyword, product, or CVE ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query (CVE ID, product name, keyword)."},
                    "limit": {"type": "integer", "description": "Maximum results to return.", "default": 10},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "stash_artifact",
            "description": "Store, list, or retrieve cross-operation artifacts (credentials, hosts, payloads, tokens).",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["add", "list", "pull"]},
                    "type": {"type": "string", "description": "Artifact type (credential, hash, host, range, payload, script, token)."},
                    "value": {"type": "string", "description": "Artifact value (for add)."},
                    "note": {"type": "string", "description": "Optional note."},
                    "id": {"type": "string", "description": "Artifact ID (for pull)."},
                },
                "required": ["action"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Vulnerability deduplication (Jaccard similarity)
# ---------------------------------------------------------------------------

def _jaccard_similarity(a: str, b: str) -> float:
    """Compute Jaccard similarity between two strings (token-level)."""
    set_a = set(a.lower().split())
    set_b = set(b.lower().split())
    if not set_a or not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union)


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

class ToolExecutor:
    """Dispatches tool calls to the appropriate handler."""

    VULN_SIMILARITY_THRESHOLD = 0.7

    def __init__(
        self,
        sandbox: Any,
        browser: Any,
        workspace_dir: str | Path,
        db: Any,
        cve_kb: Any = None,
        stash_mgr: Any = None,
        alert_engine: Any = None,
        session_id: str = None,
    ):
        self.sandbox = sandbox
        self.browser = browser
        self.workspace_dir = Path(workspace_dir) if workspace_dir else Path.cwd()
        self.db = db
        self.cve_kb = cve_kb
        self.stash_mgr = stash_mgr
        self.alert_engine = alert_engine
        self.session_id = session_id
        self._findings: list[dict] = []

        self._handlers: dict[str, Any] = {
            "execute": self._handle_execute,
            "browser_action": self._handle_browser_action,
            "web_search": self._handle_web_search,
            "create_file": self._handle_create_file,
            "read_file": self._handle_read_file,
            "create_finding": self._handle_create_finding,
            "search_cve": self._handle_search_cve,
            "stash_artifact": self._handle_stash_artifact,
        }

    async def execute_tool(self, tool_name: str, arguments: dict) -> dict:
        handler = self._handlers.get(tool_name)
        if handler is None:
            return {"success": False, "output": None, "error": f"Unknown tool: {tool_name}"}
        try:
            result = await handler(**arguments)
            # Run alert engine on results
            if self.alert_engine and isinstance(result, dict):
                text = json.dumps(result, default=str)
                await self.alert_engine.scan_output(text, source=tool_name)
            return {"success": True, "output": result, "error": None}
        except Exception as exc:
            return {"success": False, "output": None, "error": str(exc)}

    # -- execute: run command in Docker sandbox --------------------------------

    async def _handle_execute(self, command: str, timeout: int = 300) -> dict:
        timeout = min(timeout, 900)  # Cap at 15 minutes
        if self.sandbox is None:
            # Fallback: run locally (dev mode only)
            import asyncio
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return {"stdout": "", "stderr": f"Timed out after {timeout}s", "exit_code": -1, "duration": timeout}
            return {
                "stdout": stdout.decode(errors="replace")[:50000],
                "stderr": stderr.decode(errors="replace")[:10000],
                "exit_code": proc.returncode or 0,
            }

        # Use sandbox container
        container_id = self.sandbox._active_container
        if not container_id:
            self.workspace_dir.mkdir(parents=True, exist_ok=True)
            container_id = await self.sandbox.create_container(self.workspace_dir)

        result = await self.sandbox.execute(container_id, command, timeout=timeout)
        return {
            "stdout": result.stdout[:50000],
            "stderr": result.stderr[:10000],
            "exit_code": result.exit_code,
            "duration": round(result.duration, 2),
        }

    # -- browser_action: headless Chromium automation ---------------------------

    async def _handle_browser_action(
        self, action: str, url: str = None, selector: str = None, text: str = None,
    ) -> dict:
        if self.browser is None:
            return {"error": "Browser not available. Install playwright: pip install playwright && playwright install chromium"}

        if action == "navigate":
            if not url:
                return {"error": "URL required for navigate action"}
            result = await self.browser.navigate(url)
            return {"status": "navigated", "url": url, **result}
        elif action == "click":
            if not selector:
                return {"error": "Selector required for click action"}
            result = await self.browser.click(selector)
            return {"status": "clicked", "selector": selector, **result}
        elif action == "type":
            if not selector or not text:
                return {"error": "Selector and text required for type action"}
            result = await self.browser.type_text(selector, text)
            return {"status": "typed", "selector": selector, **result}
        elif action == "screenshot":
            path = self.workspace_dir / "evidence" / f"screenshot-{uuid.uuid4().hex[:8]}.png"
            path.parent.mkdir(parents=True, exist_ok=True)
            result = await self.browser.screenshot(str(path))
            return {"status": "screenshot_taken", "path": str(path), **result}
        elif action == "get_text":
            if not selector:
                return {"error": "Selector required for get_text action"}
            content = await self.browser.get_text(selector)
            return {"status": "ok", "text": content}
        elif action == "get_source":
            source = await self.browser.get_page_source()
            return {"status": "ok", "source": source[:50000]}
        else:
            return {"error": f"Unknown browser action: {action}"}

    # -- web_search: search the web for CVEs, bypasses -------------------------

    async def _handle_web_search(self, query: str, num_results: int = 5) -> dict:
        # Use httpx to search via DuckDuckGo HTML (no API key needed)
        import httpx
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                resp = await client.get(
                    "https://html.duckduckgo.com/html/",
                    params={"q": query},
                    headers={"User-Agent": "Mozilla/5.0 (compatible; ArcanumBot/3.0)"},
                )
                # Parse basic results from HTML
                results = []
                text = resp.text
                import re
                links = re.findall(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.+?)</a>', text)
                for href, title in links[:num_results]:
                    title_clean = re.sub(r'<[^>]+>', '', title).strip()
                    results.append({"url": href, "title": title_clean})
                return {"query": query, "results": results, "count": len(results)}
        except Exception as e:
            return {"query": query, "results": [], "error": str(e)}

    # -- create_file / read_file: workspace file operations --------------------

    async def _handle_create_file(self, path: str, content: str) -> dict:
        full_path = self.workspace_dir / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)
        return {"path": path, "bytes_written": len(content), "full_path": str(full_path)}

    async def _handle_read_file(self, path: str) -> dict:
        full_path = self.workspace_dir / path
        if not full_path.is_file():
            # Also check workspace/output
            alt_path = self.workspace_dir / "output" / path
            if alt_path.is_file():
                full_path = alt_path
            else:
                raise FileNotFoundError(f"File not found: {path}")
        content = full_path.read_text(errors="replace")
        return {"path": path, "content": content[:100000], "size": len(content)}

    # -- create_finding: record a verified vulnerability -----------------------

    async def _handle_create_finding(
        self, title: str, type: str, severity: str, cvss_score: float,
        affected: dict, evidence: dict, poc: dict, remediation: str,
    ) -> dict:
        # Deduplicate via Jaccard similarity
        for existing in self._findings:
            sig_new = f"{title} {type} {json.dumps(affected)}"
            sig_old = f"{existing['title']} {existing['type']} {json.dumps(existing.get('affected', {}))}"
            if _jaccard_similarity(sig_new, sig_old) > self.VULN_SIMILARITY_THRESHOLD:
                return {
                    "id": existing["id"],
                    "status": "duplicate",
                    "message": f"Similar finding already exists: {existing['title']}",
                }

        finding_id = f"finding-{uuid.uuid4().hex[:8]}"
        finding = {
            "id": finding_id,
            "session_id": self.session_id,
            "title": title,
            "type": type,
            "severity": severity,
            "cvss_score": cvss_score,
            "affected": affected,
            "evidence": evidence,
            "poc": poc,
            "remediation": remediation,
            "verified": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._findings.append(finding)

        # Persist to database
        if self.db:
            try:
                await self.db.execute(
                    """INSERT INTO findings (id, session_id, title, type, severity, cvss_score,
                       affected, evidence, poc, remediation, verified)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (finding_id, self.session_id, title, type, severity, cvss_score,
                     json.dumps(affected), json.dumps(evidence), json.dumps(poc),
                     remediation, True),
                )
                if self.session_id:
                    await self.db.execute(
                        "UPDATE sessions SET findings_count = findings_count + 1 WHERE id = ?",
                        (self.session_id,),
                    )
            except Exception:
                pass  # Don't fail tool execution on DB error

        # Write finding to workspace
        findings_dir = self.workspace_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        (findings_dir / f"{finding_id}.json").write_text(json.dumps(finding, indent=2))

        # Trigger alerts
        if self.alert_engine:
            await self.alert_engine.scan_finding(finding)

        return {"id": finding_id, "finding": finding, "status": "created"}

    # -- search_cve: query local CVE knowledge base ----------------------------

    async def _handle_search_cve(self, query: str, limit: int = 10) -> dict:
        if self.cve_kb:
            try:
                results = await self.cve_kb.search(query, limit=limit)
                return {
                    "query": query,
                    "results": [
                        {
                            "id": r.id,
                            "description": r.description[:300] if r.description else "",
                            "cvss_score": r.cvss_score,
                            "exploit_available": r.exploit_available,
                        }
                        for r in results
                    ],
                    "count": len(results),
                }
            except Exception as e:
                return {"query": query, "results": [], "error": str(e)}

        # Fallback: search web for CVEs
        return await self._handle_web_search(f"CVE {query} site:nvd.nist.gov", num_results=limit)

    # -- stash_artifact: cross-operation artifact sharing ----------------------

    async def _handle_stash_artifact(
        self, action: str, type: str = None, value: str = None,
        note: str = None, id: str = None,
    ) -> dict:
        if self.stash_mgr:
            if action == "add":
                if not type or not value:
                    return {"error": "type and value required for add"}
                from ..core.models import StashType
                try:
                    item = await self.stash_mgr.add(StashType(type), value, note, self.session_id)
                    return {"id": item.id, "status": "added", "type": type}
                except ValueError:
                    return {"error": f"Invalid stash type: {type}. Use: credential, hash, host, range, payload, script, token"}
            elif action == "list":
                items = await self.stash_mgr.list()
                return {
                    "items": [
                        {"id": i.id, "type": i.type if isinstance(i.type, str) else i.type.value,
                         "value": i.value[:50], "note": i.note}
                        for i in items[:20]
                    ],
                    "count": len(items),
                }
            elif action == "pull":
                if not id:
                    return {"error": "id required for pull"}
                item = await self.stash_mgr.get(id)
                if item:
                    return {"id": item.id, "type": item.type if isinstance(item.type, str) else item.type.value,
                            "value": item.value, "note": item.note}
                return {"error": f"Artifact not found: {id}"}

        # Fallback: in-memory stash
        if not hasattr(self, '_mem_stash'):
            self._mem_stash = []
        if action == "add":
            art_id = f"stash-{uuid.uuid4().hex[:8]}"
            self._mem_stash.append({"id": art_id, "type": type, "value": value, "note": note})
            return {"id": art_id, "status": "added"}
        elif action == "list":
            return {"items": self._mem_stash, "count": len(self._mem_stash)}
        elif action == "pull":
            for art in self._mem_stash:
                if art["id"] == id:
                    return art
            return {"error": f"Artifact not found: {id}"}
        return {"error": f"Unknown stash action: {action}"}
