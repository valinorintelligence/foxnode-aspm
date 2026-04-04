"""CVE Knowledge Base endpoints."""
from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/search")
async def search_cve(request: Request, q: str, limit: int = 10):
    results = await request.app.state.cve_kb.search(q, limit=limit)
    return {
        "results": [
            {
                "id": r.id,
                "description": r.description,
                "cvss_score": r.cvss_score,
                "cvss_vector": r.cvss_vector,
                "exploit_available": r.exploit_available,
            }
            for r in results
        ]
    }


@router.get("/stats")
async def cve_stats(request: Request):
    count = await request.app.state.cve_kb.count()
    return {"total_cves": count}


@router.get("/{cve_id}")
async def get_cve(request: Request, cve_id: str):
    entry = await request.app.state.cve_kb.get(cve_id)
    if not entry:
        return {"error": "CVE not found"}, 404
    return {
        "cve": {
            "id": entry.id,
            "description": entry.description,
            "cvss_score": entry.cvss_score,
            "cvss_vector": entry.cvss_vector,
            "cwe_ids": entry.cwe_ids,
            "affected_products": entry.affected_products,
            "exploit_available": entry.exploit_available,
        }
    }
