"""
routers/vulnerabilities.py — Vulnerability list, detail, and remediation endpoints.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Vulnerability
from app.ml_service import score_vulnerability
from app.schemas import VulnerabilityResponse

router = APIRouter()


def _vuln_or_404(vuln_id: int, db: Session) -> Vulnerability:
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id} not found")
    return vuln


def _vuln_to_response(v: Vulnerability, include_explainability: bool = False) -> VulnerabilityResponse:
    explainability = None
    if include_explainability:
        asset = v.asset
        asset_dict = {"criticality": asset.criticality, "exposure": asset.exposure} if asset else {}
        vuln_dict = {
            "cvss_score": v.cvss_score,
            "vuln_type": v.vuln_type,
            "exploit_available": v.exploit_available,
            "in_threat_feed": v.in_threat_feed,
            "auth_required": v.auth_required,
            "attack_vector": v.attack_vector,
            "historical_recurrence": v.historical_recurrence,
            "days_since_last_scan": v.days_since_last_scan,
        }
        try:
            ml_result = score_vulnerability(vuln_dict, asset_dict)
            explainability = ml_result.get("explainability")
        except Exception:  # noqa: BLE001
            explainability = None

    return VulnerabilityResponse(
        id=v.id,
        scan_id=v.scan_id,
        asset_id=v.asset_id,
        cve_id=v.cve_id,
        title=v.title,
        description=v.description,
        severity=v.severity,
        cvss_score=v.cvss_score,
        cvss_vector=v.cvss_vector,
        vuln_type=v.vuln_type,
        exploit_available=v.exploit_available,
        in_threat_feed=v.in_threat_feed,
        auth_required=v.auth_required,
        attack_vector=v.attack_vector,
        historical_recurrence=v.historical_recurrence,
        days_since_last_scan=v.days_since_last_scan,
        priority_score=v.priority_score,
        risk_tier=v.risk_tier,
        is_remediated=v.is_remediated,
        discovered_at=v.discovered_at,
        explainability=explainability,
    )


@router.get("", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    risk_tier: Optional[str] = None,
    asset_id: Optional[int] = None,
    remediated: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    """
    List all vulnerabilities sorted by priority_score DESC.
    Supports optional filters: risk_tier, asset_id, remediated.
    """
    stmt = select(Vulnerability)
    if risk_tier:
        stmt = stmt.where(Vulnerability.risk_tier == risk_tier)
    if asset_id is not None:
        stmt = stmt.where(Vulnerability.asset_id == asset_id)
    if remediated is not None:
        stmt = stmt.where(Vulnerability.is_remediated == remediated)
    stmt = stmt.order_by(Vulnerability.priority_score.desc().nullslast())
    vulns = db.execute(stmt).scalars().all()
    return [_vuln_to_response(v) for v in vulns]


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Get a single vulnerability with full explainability breakdown."""
    vuln = _vuln_or_404(vuln_id, db)
    return _vuln_to_response(vuln, include_explainability=True)


@router.patch("/{vuln_id}/remediate", response_model=VulnerabilityResponse)
def remediate_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Mark a vulnerability as remediated."""
    vuln = _vuln_or_404(vuln_id, db)
    if vuln.is_remediated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Vulnerability {vuln_id} is already marked as remediated.",
        )
    vuln.is_remediated = True
    db.commit()
    db.refresh(vuln)
    return _vuln_to_response(vuln)
