"""Stash endpoints."""
from fastapi import APIRouter, Request
from pydantic import BaseModel

from ...core.models import StashType

router = APIRouter()


class AddStashRequest(BaseModel):
    type: str
    value: str
    note: str | None = None
    session_id: str | None = None


@router.get("/")
async def list_stash(request: Request, type: str = None):
    filter_type = StashType(type) if type else None
    items = await request.app.state.stash_mgr.list(filter_type)
    return {
        "items": [
            {
                "id": i.id,
                "type": i.type if isinstance(i.type, str) else i.type.value,
                "value": i.value,
                "note": i.note,
                "created_at": str(i.created_at),
            }
            for i in items
        ]
    }


@router.post("/")
async def add_stash(request: Request, body: AddStashRequest):
    item = await request.app.state.stash_mgr.add(
        StashType(body.type), body.value, body.note, body.session_id,
    )
    return {
        "item": {
            "id": item.id,
            "type": item.type.value,
            "value": item.value,
            "note": item.note,
        }
    }


@router.get("/{item_id}")
async def get_stash(request: Request, item_id: str):
    item = await request.app.state.stash_mgr.get(item_id)
    if not item:
        return {"error": "Not found"}, 404
    return {
        "item": {
            "id": item.id,
            "type": item.type if isinstance(item.type, str) else item.type.value,
            "value": item.value,
            "note": item.note,
        }
    }


@router.post("/{item_id}/pull")
async def pull_stash(request: Request, item_id: str, session_id: str):
    item = await request.app.state.stash_mgr.pull(item_id, session_id)
    if not item:
        return {"error": "Not found"}, 404
    return {"status": "pulled", "item_id": item_id}


@router.delete("/{item_id}")
async def delete_stash(request: Request, item_id: str):
    await request.app.state.stash_mgr.delete(item_id)
    return {"status": "deleted"}
