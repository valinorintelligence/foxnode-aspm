"""Tool management endpoints."""
import json
from pathlib import Path
from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/")
async def list_tools():
    registry_path = Path(__file__).parent.parent.parent / "tools" / "registry.json"
    with open(registry_path) as f:
        registry = json.load(f)
    return {"tools": registry["tools"], "total": len(registry["tools"])}


@router.get("/categories")
async def list_categories():
    registry_path = Path(__file__).parent.parent.parent / "tools" / "registry.json"
    with open(registry_path) as f:
        registry = json.load(f)
    categories = {}
    for tool in registry["tools"]:
        cat = tool["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(tool["name"])
    return {"categories": categories}


@router.get("/{tool_name}")
async def get_tool(tool_name: str):
    registry_path = Path(__file__).parent.parent.parent / "tools" / "registry.json"
    with open(registry_path) as f:
        registry = json.load(f)
    for tool in registry["tools"]:
        if tool["name"] == tool_name:
            return {"tool": tool}
    return {"error": f"Tool '{tool_name}' not found"}, 404
