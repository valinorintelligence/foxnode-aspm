"""Base tool wrapper and registry loader for Arcanum security tools."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ToolResult:
    """Result from executing a security tool."""

    name: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    parsed_data: dict = field(default_factory=dict)


class ToolWrapper:
    """Wraps a security tool with its registry configuration for sandboxed execution."""

    def __init__(self, name: str, config: dict) -> None:
        self.name = name
        self.category: str = config.get("category", "")
        self.description: str = config.get("description", "")
        self.binary: str = config.get("binary", name)
        self.default_args: list[str] = config.get("default_args", [])
        self.risk_level: str = config.get("risk_level", "medium")
        self.stealth: str = config.get("stealth", "active")
        self.default_timeout: int = config.get("timeout", 300)

    async def run(
        self,
        sandbox: Any,
        args: list[str],
        timeout: int | None = None,
    ) -> ToolResult:
        """Execute the tool inside a sandbox container.

        Args:
            sandbox: A SandboxManager instance with an active container.
            args: Command-line arguments to pass to the tool binary.
            timeout: Override the default timeout in seconds.

        Returns:
            ToolResult with stdout, stderr, exit code, and parsed output.
        """
        effective_timeout = timeout if timeout is not None else self.default_timeout
        full_args = self.default_args + args
        command = " ".join([self.binary] + full_args)

        start = time.time()
        result = await sandbox.execute(
            sandbox._active_container,
            command,
            timeout=effective_timeout,
        )
        duration = time.time() - start

        parsed = self.parse_output(result.stdout)

        return ToolResult(
            name=self.name,
            command=command,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration=duration,
            parsed_data=parsed,
        )

    def parse_output(self, raw_output: str) -> dict:
        """Parse raw tool output into structured data.

        Base implementation returns the raw output keyed by the tool name.
        Subclasses should override for tool-specific parsing.
        """
        lines = [line for line in raw_output.strip().splitlines() if line.strip()]
        return {
            "tool": self.name,
            "raw_lines": lines,
            "line_count": len(lines),
        }

    def __repr__(self) -> str:
        return f"ToolWrapper(name={self.name!r}, category={self.category!r}, risk={self.risk_level!r})"


def load_registry() -> dict:
    """Load the tool registry from registry.json.

    Returns:
        The raw registry dict with a ``tools`` list.
    """
    registry_path = Path(__file__).parent / "registry.json"
    with open(registry_path, "r") as f:
        return json.load(f)


def load_registry_map() -> dict[str, dict]:
    """Load the tool registry as a name→config mapping."""
    data = load_registry()
    return {tool["name"]: tool for tool in data.get("tools", [])}
