"""
routers/vulnerabilities.py — Vulnerability list, detail, and remediation endpoints.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import verify_api_key
from app.database import get_db
from app.models import Vulnerability
from app.routers.helpers import vuln_to_response
from app.schemas import VulnerabilityResponse

router = APIRouter()


def _vuln_or_404(vuln_id: int, db: Session) -> Vulnerability:
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id} not found")
    return vuln


@router.get("", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    risk_tier: Optional[str] = None,
    asset_id: Optional[int] = None,
    remediated: Optional[bool] = None,
    limit: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """
    List vulnerabilities sorted by priority_score DESC.
    Does NOT compute full explainability to keep response lightweight.
    """
    stmt = select(Vulnerability)
    if risk_tier:
        stmt = stmt.where(Vulnerability.risk_tier == risk_tier)
    if asset_id is not None:
        stmt = stmt.where(Vulnerability.asset_id == asset_id)
    if remediated is not None:
        stmt = stmt.where(Vulnerability.is_remediated == remediated)

    stmt = stmt.order_by(Vulnerability.priority_score.desc().nullslast(), Vulnerability.id.asc())
    if limit:
        stmt = stmt.limit(limit)

    vulns = db.execute(stmt).scalars().all()
    return [vuln_to_response(v, include_explainability=True) for v in vulns]


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Fetch single vulnerability with detailed explainability factors."""
    vuln = _vuln_or_404(vuln_id, db)
    return vuln_to_response(vuln, include_explainability=True)


@router.patch("/{vuln_id}/remediate", response_model=VulnerabilityResponse)
def remediate_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_api_key),
):
    """Mark a vulnerability as remediated (Protected by X-API-Key)."""
    vuln = _vuln_or_404(vuln_id, db)
    vuln.is_remediated = True
    db.commit()
    db.refresh(vuln)
    return vuln_to_response(vuln, include_explainability=False)
