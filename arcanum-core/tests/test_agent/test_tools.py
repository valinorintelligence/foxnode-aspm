"""Tests for tool registry and definitions."""
import json
from pathlib import Path

from arcanum.tools.base import load_registry


def test_registry_loads():
    registry = load_registry()
    assert "tools" in registry
    assert len(registry["tools"]) == 40


def test_all_categories_present():
    registry = load_registry()
    categories = {t["category"] for t in registry["tools"]}
    expected = {"recon", "web", "network", "creds", "exploit", "post", "osint"}
    assert categories == expected


def test_tool_has_required_fields():
    registry = load_registry()
    for tool in registry["tools"]:
        assert "name" in tool
        assert "category" in tool
        assert "description" in tool
        assert "binary" in tool
        assert "risk_level" in tool
        assert tool["risk_level"] in ("low", "medium", "high")
