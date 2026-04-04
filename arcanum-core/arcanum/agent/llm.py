"""Ollama LLM client with extended thinking, model detection, and streaming."""

from __future__ import annotations

import json
from typing import AsyncGenerator

import httpx


class OllamaClient:
    """Client for the Ollama API with extended thinking support."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "qwen3:32b",
        timeout: float = 300.0,
        num_ctx: int = 131072,
        temperature: float = 0.15,
        num_predict: int = 32768,
        repeat_penalty: float = 1.05,
        enable_thinking: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.num_ctx = num_ctx
        self.temperature = temperature
        self.num_predict = num_predict
        self.repeat_penalty = repeat_penalty
        self.enable_thinking = enable_thinking
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)

    async def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> dict:
        """Send a chat completion request to Ollama. Returns the response message."""
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "num_ctx": self.num_ctx,
                "temperature": self.temperature,
                "num_predict": self.num_predict,
                "repeat_penalty": self.repeat_penalty,
            },
        }
        if tools:
            payload["tools"] = tools
        if self.enable_thinking:
            payload["options"]["num_predict"] = max(self.num_predict, 16384)

        resp = await self._client.post("/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {})

    async def chat_stream(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
    ) -> AsyncGenerator[dict, None]:
        """Stream a chat completion, yielding chunks."""
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {
                "num_ctx": self.num_ctx,
                "temperature": self.temperature,
                "num_predict": self.num_predict,
                "repeat_penalty": self.repeat_penalty,
            },
        }
        if tools:
            payload["tools"] = tools

        async with self._client.stream("POST", "/api/chat", json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    yield chunk
                except json.JSONDecodeError:
                    continue

    async def list_models(self) -> list[dict]:
        """List available models with metadata."""
        resp = await self._client.get("/api/tags")
        resp.raise_for_status()
        data = resp.json()
        return data.get("models", [])

    async def show_model(self, model_name: str = None) -> dict:
        """Get model metadata (parameters, size, quantization)."""
        resp = await self._client.post("/api/show", json={"name": model_name or self.model})
        resp.raise_for_status()
        return resp.json()

    async def detect_capabilities(self) -> dict:
        """Auto-detect model capabilities (tool calling, thinking, context size)."""
        try:
            info = await self.show_model()
            params = info.get("parameters", "")
            modelfile = info.get("modelfile", "")
            template = info.get("template", "")

            # Detect capabilities
            has_tool_calling = "tool" in template.lower() or "function" in template.lower()
            has_thinking = "think" in template.lower() or "think" in params.lower()
            num_params = info.get("details", {}).get("parameter_size", "unknown")

            return {
                "model": self.model,
                "parameters": num_params,
                "tool_calling": has_tool_calling,
                "thinking": has_thinking,
                "quantization": info.get("details", {}).get("quantization_level", "unknown"),
                "family": info.get("details", {}).get("family", "unknown"),
            }
        except Exception as e:
            return {"model": self.model, "error": str(e)}

    async def check_health(self) -> bool:
        """Check whether the Ollama server is reachable."""
        try:
            resp = await self._client.get("/api/tags")
            return resp.status_code == 200
        except (httpx.HTTPError, ConnectionError):
            return False

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
