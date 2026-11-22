"""
routers/scans.py — Scan list, upload, and detail endpoints.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import verify_api_key
from app.database import get_db
from app.ingest import ingest_scan
from app.models import Scan, Vulnerability
from app.routers.helpers import vuln_to_response
from app.schemas import (
    ScanResponse,
    ScanUploadPayload,
    ScanUploadResponse,
    VulnerabilityResponse,
)

router = APIRouter()
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB max body size


def _scan_or_404(scan_id: int, db: Session) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@router.get("", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    stmt = select(Scan).order_by(Scan.scan_date.desc(), Scan.id.desc())
    return db.execute(stmt).scalars().all()


@router.post("/upload", response_model=ScanUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_scan(
    request: Request,
    payload: ScanUploadPayload,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_api_key),
):
    """
    Ingest scan findings. Accepts both raw scanner documents:
      { "scan_metadata": {...}, "findings": [...] }
    and wrapped payloads:
      { "scanner_name": "...", "vulnerabilities": [...] }
    """
    # Enforce size ceiling
    body = await request.body()
    if len(body) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Scan payload exceeds 5 MB size limit",
        )

    # Adapter to normalize metadata & findings list
    meta: Dict[str, Any] = {}
    if payload.scan_metadata:
        meta = payload.scan_metadata.model_dump()
    else:
        meta = {
            "scanner": payload.scanner_name or "API Upload Scanner",
            "scan_date": payload.scan_date,
            "target": payload.target_range,
        }

    findings_list = payload.findings or payload.vulnerabilities or []
    if not findings_list:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload contains no vulnerabilities or findings",
        )

    result = ingest_scan(meta, findings_list, db)

return ScanUploadResponse(
    scan_id=result.scan.id,
    total_findings=len(findings_list),
    scored=result.scored,
    skipped=result.skipped,
    warnings=result.warnings,
)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    return _scan_or_404(scan_id, db)


@router.get("/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
def list_scan_vulnerabilities(scan_id: int, db: Session = Depends(get_db)):
    _scan_or_404(scan_id, db)
    stmt = select(Vulnerability).where(Vulnerability.scan_id == scan_id).order_by(
        Vulnerability.priority_score.desc().nullslast(),
        Vulnerability.id.asc(),
    )
    vulns = db.execute(stmt).scalars().all()
    return [vuln_to_response(v, include_explainability=False) for v in vulns]
