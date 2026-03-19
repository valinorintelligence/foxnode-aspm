from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.integration import ScanImport
from app.models.finding import Finding
from app.models.product import Engagement, Test
from app.parsers.registry import ParserRegistry
from app.schemas.schemas import ScanImportResponse

router = APIRouter(prefix="/scans", tags=["Scan Imports"])


@router.get("/parsers")
async def list_parsers():
    return ParserRegistry.list_parsers()


@router.post("/import", response_model=ScanImportResponse)
async def import_scan(
    file: UploadFile = File(...),
    scanner: str = Form(...),
    product_id: int = Form(...),
    engagement_id: int = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    parser = ParserRegistry.get_parser(scanner)
    if not parser:
        raise HTTPException(status_code=400, detail=f"Unsupported scanner: {scanner}")

    content = await file.read()

    # Create or get engagement
    if not engagement_id:
        engagement = Engagement(
            name=f"Auto-import: {scanner}",
            product_id=product_id,
            lead_id=current_user.id,
        )
        db.add(engagement)
        await db.flush()
        engagement_id = engagement.id

    test = Test(
        title=f"{scanner} scan - {file.filename}",
        test_type=scanner,
        scan_type=parser.scan_type,
        engagement_id=engagement_id,
    )
    db.add(test)
    await db.flush()

    scan_import = ScanImport(
        filename=file.filename,
        scan_type=parser.scan_type,
        scanner=scanner,
        product_id=product_id,
        engagement_id=engagement_id,
        test_id=test.id,
        imported_by_id=current_user.id,
    )
    db.add(scan_import)
    await db.flush()

    try:
        findings_data = parser.parse(content)
        created = 0
        duplicates = 0

        for f_data in findings_data:
            finding = Finding(
                title=f_data.get("title", "Untitled"),
                description=f_data.get("description"),
                severity=f_data.get("severity", "medium"),
                cvss_score=f_data.get("cvss_score"),
                cwe=f_data.get("cwe"),
                cve=f_data.get("cve"),
                scanner=scanner,
                tool_type=parser.scan_type,
                file_path=f_data.get("file_path"),
                line_number=f_data.get("line_number"),
                component=f_data.get("component"),
                component_version=f_data.get("component_version"),
                mitigation=f_data.get("mitigation"),
                impact=f_data.get("impact"),
                references=f_data.get("references"),
                unique_id_from_tool=f_data.get("unique_id"),
                product_id=product_id,
                test_id=test.id,
                reporter_id=current_user.id,
            )
            finding.compute_hash()

            # Check for duplicates
            existing = await db.execute(
                select(Finding).where(
                    Finding.hash_code == finding.hash_code,
                    Finding.product_id == product_id,
                    Finding.is_duplicate == False,
                )
            )
            if existing.scalar_one_or_none():
                finding.is_duplicate = True
                duplicates += 1
            else:
                created += 1

            db.add(finding)

        scan_import.findings_created = created
        scan_import.findings_duplicates = duplicates
        scan_import.status = "completed"
        test.findings_count = created + duplicates

    except Exception as e:
        scan_import.status = "failed"
        scan_import.error_message = str(e)

    await db.flush()
    await db.refresh(scan_import)
    return scan_import


@router.get("/history", response_model=list[ScanImportResponse])
async def scan_history(
    product_id: int = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(ScanImport).order_by(ScanImport.created_at.desc()).limit(50)
    if product_id:
        query = query.where(ScanImport.product_id == product_id)
    result = await db.execute(query)
    return result.scalars().all()
