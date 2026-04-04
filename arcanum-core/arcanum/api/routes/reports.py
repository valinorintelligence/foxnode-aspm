"""Report generation endpoints."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ...core.config import get_config
from ...core.reports import ReportConfig

router = APIRouter()


class GenerateReportRequest(BaseModel):
    session_name: str
    formats: list[str] = ["html", "json", "md"]
    title: str | None = None
    classification: str = "CONFIDENTIAL"


@router.post("/generate")
async def generate_report(request: Request, body: GenerateReportRequest):
    session = await request.app.state.session_mgr.get_session(body.session_name)
    if not session:
        return {"error": "Session not found"}, 404

    findings = await request.app.state.db.fetch_all(
        "SELECT * FROM findings WHERE session_id = ?", (session["id"],)
    )
    parsed_findings = []
    for f in findings:
        fd = dict(f)
        for field in ("affected", "evidence", "poc", "cwe_ids"):
            if fd.get(field) and isinstance(fd[field], str):
                try:
                    fd[field] = json.loads(fd[field])
                except json.JSONDecodeError:
                    pass
        parsed_findings.append(fd)

    config = ReportConfig(
        title=body.title or f"Security Assessment - {session.get('target', 'Unknown')}",
        classification=body.classification,
    )

    output_dir = get_config().ops_dir / body.session_name / "reports"
    results = await request.app.state.report_engine.export(
        session=session,
        findings=parsed_findings,
        output_dir=output_dir,
        formats=body.formats,
        config=config,
    )

    return {"reports": {fmt: str(path) for fmt, path in results.items()}}


@router.get("/download/{session_name}/{format}")
async def download_report(session_name: str, format: str):
    config = get_config()
    report_dir = config.ops_dir / session_name / "reports"
    if not report_dir.exists():
        return {"error": "No reports found"}, 404

    files = list(report_dir.glob(f"*.{format}"))
    if not files:
        return {"error": f"No {format} report found"}, 404

    return FileResponse(files[-1], filename=files[-1].name)
