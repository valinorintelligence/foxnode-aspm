from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.finding import Finding
from app.services.jira_service import JiraService

router = APIRouter(prefix="/jira", tags=["Jira"])


class CreateIssueRequest(BaseModel):
    project_key: str = "SEC"
    issue_type: str = "Bug"


class SyncRequest(BaseModel):
    jira_key: str


class JiraSearchRequest(BaseModel):
    jql: str
    max_results: int = 50


@router.post("/create-issue/{finding_id}")
async def create_jira_issue(
    finding_id: int,
    body: CreateIssueRequest = CreateIssueRequest(),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Create a Jira issue from an existing finding."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    service = JiraService()
    try:
        jira_response = await service.create_issue(
            finding,
            project_key=body.project_key,
            issue_type=body.issue_type,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to create Jira issue: {exc}")

    return {
        "message": "Jira issue created",
        "jira_key": jira_response.get("key"),
        "jira_id": jira_response.get("id"),
        "finding_id": finding_id,
    }


@router.post("/sync/{finding_id}")
async def sync_jira_status(
    finding_id: int,
    body: SyncRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Sync the status of a Jira issue back to the local finding."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    service = JiraService()
    try:
        status_info = await service.sync_status(finding_id, body.jira_key)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to sync Jira status: {exc}")

    return {
        "finding_id": finding_id,
        "jira_key": body.jira_key,
        "jira_status": status_info.get("status"),
        "jira_status_category": status_info.get("status_category"),
    }


@router.get("/status")
async def jira_connection_status(
    current_user=Depends(get_current_user),
):
    """Check whether the Jira integration is connected and reachable."""
    service = JiraService()
    return await service.check_connection()
