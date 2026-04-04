"""Findings endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

router = APIRouter()


class CreateFindingRequest(BaseModel):
    session_id: str
    title: str
    type: str | None = None
    severity: str = "medium"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected: dict | None = None
    evidence: dict | None = None
    poc: dict | None = None
    cve_id: str | None = None
    cwe_ids: list[str] | None = None
    remediation: str | None = None
    verified: bool = False


@router.get("/")
async def list_findings(request: Request, session_id: str = None):
    if session_id:
        rows = await request.app.state.db.fetch_all(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at DESC", (session_id,)
        )
    else:
        rows = await request.app.state.db.fetch_all("SELECT * FROM findings ORDER BY created_at DESC")
    return {"findings": rows}


@router.post("/")
async def create_finding(request: Request, body: CreateFindingRequest):
    import uuid, json
    finding_id = f"finding-{uuid.uuid4().hex[:8]}"
    await request.app.state.db.execute(
        """INSERT INTO findings (id, session_id, title, type, severity, cvss_score, cvss_vector,
           affected, evidence, poc, cve_id, cwe_ids, remediation, verified)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (finding_id, body.session_id, body.title, body.type, body.severity,
         body.cvss_score, body.cvss_vector,
         json.dumps(body.affected) if body.affected else None,
         json.dumps(body.evidence) if body.evidence else None,
         json.dumps(body.poc) if body.poc else None,
         body.cve_id, json.dumps(body.cwe_ids) if body.cwe_ids else None,
         body.remediation, body.verified),
    )
    # Update session findings count
    await request.app.state.db.execute(
        "UPDATE sessions SET findings_count = findings_count + 1 WHERE id = ?", (body.session_id,)
    )
    # Alert engine scan
    await request.app.state.alert_engine.scan_finding(body.model_dump())
    return {"finding": {"id": finding_id, **body.model_dump()}}


@router.get("/{finding_id}")
async def get_finding(request: Request, finding_id: str):
    row = await request.app.state.db.fetch_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
    if not row:
        raise HTTPException(404, "Finding not found")
    return {"finding": row}
