"""Docker-based sandbox for secure tool execution."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecutionResult:
    """Result of executing a command inside a Docker container."""

    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration: float


class SandboxManager:
    """Manages Docker containers for sandboxed security tool execution."""

    DEFAULT_IMAGE = "arcanum/kali-sandbox:latest"
    DEFAULT_TIMEOUT = 300
    MEMORY_LIMIT = "4g"

    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.image = image
        self.timeout = timeout
        self._containers: list[str] = []
        self._active_container: str | None = None

    async def ensure_image(self) -> bool:
        """Check if the sandbox Docker image exists locally.

        Returns:
            True if the image is available, False otherwise.
        """
        proc = await asyncio.create_subprocess_exec(
            "docker", "image", "inspect", self.image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0

    async def create_container(
        self,
        workspace_dir: Path,
        network: bool = True,
    ) -> str:
        """Create a new sandboxed Docker container.

        Args:
            workspace_dir: Host directory to mount at /workspace inside the container.
            network: Whether to enable network access. Defaults to True.

        Returns:
            The container ID string.
        """
        container_name = f"arcanum-sandbox-{uuid.uuid4().hex[:12]}"
        workspace_abs = str(workspace_dir.resolve())

        cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "--memory", self.MEMORY_LIMIT,
            "--security-opt", "no-new-privileges",
            "-v", f"{workspace_abs}:/workspace",
        ]

        if not network:
            cmd.extend(["--network", "none"])

        cmd.append(self.image)
        cmd.extend(["tail", "-f", "/dev/null"])  # Keep container alive

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(
                f"Failed to create container: {stderr.decode().strip()}"
            )

        container_id = stdout.decode().strip()
        self._containers.append(container_id)
        self._active_container = container_id
        return container_id

    async def execute(
        self,
        container_id: str,
        command: str,
        timeout: int | None = None,
    ) -> ExecutionResult:
        """Execute a command inside a running container.

        Args:
            container_id: The target container ID or name.
            command: Shell command to execute.
            timeout: Timeout in seconds; uses instance default if None.

        Returns:
            ExecutionResult with captured output and timing.
        """
        effective_timeout = timeout if timeout is not None else self.timeout

        start = time.time()
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_id, "sh", "-c", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=effective_timeout if effective_timeout > 0 else None,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            duration = time.time() - start
            return ExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {effective_timeout}s",
                duration=duration,
            )

        duration = time.time() - start
        return ExecutionResult(
            command=command,
            exit_code=proc.returncode or 0,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            duration=duration,
        )

    async def stop_container(self, container_id: str) -> None:
        """Stop a running container.

        Args:
            container_id: The container ID or name to stop.
        """
        proc = await asyncio.create_subprocess_exec(
            "docker", "stop", "-t", "5", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

    async def cleanup(self) -> None:
        """Stop and remove all containers managed by this instance."""
        for container_id in self._containers:
            try:
                stop = await asyncio.create_subprocess_exec(
                    "docker", "stop", "-t", "3", container_id,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await stop.wait()

                rm = await asyncio.create_subprocess_exec(
                    "docker", "rm", "-f", container_id,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await rm.wait()
            except Exception:
                pass

        self._containers.clear()
        self._active_container = None
