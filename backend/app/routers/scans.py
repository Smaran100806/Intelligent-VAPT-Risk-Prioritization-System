"""
routers/scans.py — Scan list, upload, and detail endpoints.
"""

from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Scan, Vulnerability, VulnerabilityHistory
from app.ml_service import score_vulnerability
from app.schemas import (
    ScanResponse,
    ScanUploadPayload,
    ScanUploadResponse,
    VulnerabilityResponse,
)

router = APIRouter()


def _scan_or_404(scan_id: int, db: Session) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@router.get("", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    """List all scans ordered newest first."""
    stmt = select(Scan).order_by(Scan.scan_date.desc())
    return db.execute(stmt).scalars().all()


@router.post("/upload", response_model=ScanUploadResponse, status_code=status.HTTP_201_CREATED)
def upload_scan(payload: ScanUploadPayload, db: Session = Depends(get_db)):
    """
    Persist a full scan upload:
    1. Create a Scan record.
    2. For each finding, resolve the asset by IP, run ML scoring.
    3. Track recurrence in VulnerabilityHistory.
    4. Return summary.
    """
    # 1. Create scan record
    scan = Scan(
        scanner_name=payload.scanner_name,
        scan_date=payload.scan_date,
        target_range=payload.target_range,
        status="completed",
    )
    db.add(scan)
    db.flush()  # get scan.id without commit

    # Build asset lookup by ip_address for quick resolution
    all_assets_stmt = select(Asset)
    all_assets = db.execute(all_assets_stmt).scalars().all()
    ip_to_asset = {a.ip_address: a for a in all_assets if a.ip_address}
    id_to_asset = {a.id: a for a in all_assets}

    scored = 0
    skipped = 0

    for finding in payload.vulnerabilities:
        finding_data = finding.model_dump()

        # Resolve asset
        asset: Asset | None = None
        if finding.asset_id and finding.asset_id in id_to_asset:
            asset = id_to_asset[finding.asset_id]
        # Also try host field if present (upload may carry host IP)
        host_ip = finding_data.get("host")
        if asset is None and host_ip and host_ip in ip_to_asset:
            asset = ip_to_asset[host_ip]

        asset_dict = {}
        if asset:
            asset_dict = {
                "criticality": asset.criticality,
                "exposure": asset.exposure,
            }

        # Track recurrence
        recurrence = 0
        if finding.cve_id:
            asset_id_val = asset.id if asset else None
            hist_stmt = select(VulnerabilityHistory).where(
                VulnerabilityHistory.cve_id == finding.cve_id,
                VulnerabilityHistory.asset_id == asset_id_val,
            )
            hist = db.execute(hist_stmt).scalar_one_or_none()
            if hist:
                hist.recurrence_count += 1
                hist.last_seen = datetime.now(timezone.utc)
                recurrence = hist.recurrence_count
            else:
                hist = VulnerabilityHistory(
                    cve_id=finding.cve_id,
                    asset_id=asset_id_val,
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    recurrence_count=1,
                )
                db.add(hist)

        # ML scoring
        vuln_dict = {
            "cvss_score": finding.cvss_score,
            "vuln_type": finding.vuln_type,
            "exploit_available": finding.exploit_available,
            "in_threat_feed": finding.in_threat_feed,
            "auth_required": finding.auth_required,
            "attack_vector": finding.attack_vector,
            "historical_recurrence": recurrence,
            "days_since_last_scan": finding.days_since_last_scan,
        }
        try:
            ml_result = score_vulnerability(vuln_dict, asset_dict)
            priority_score = ml_result["priority_score"]
            risk_tier = ml_result["risk_tier"]
            scored += 1
        except Exception:  # noqa: BLE001
            priority_score = None
            risk_tier = None
            skipped += 1

        # Create vulnerability record
        vuln = Vulnerability(
            scan_id=scan.id,
            asset_id=asset.id if asset else None,
            cve_id=finding.cve_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            cvss_vector=finding.cvss_vector,
            vuln_type=finding.vuln_type,
            exploit_available=finding.exploit_available,
            in_threat_feed=finding.in_threat_feed,
            auth_required=finding.auth_required,
            attack_vector=finding.attack_vector,
            historical_recurrence=recurrence,
            days_since_last_scan=finding.days_since_last_scan,
            priority_score=priority_score,
            risk_tier=risk_tier,
            is_remediated=False,
        )
        db.add(vuln)

    db.commit()
    db.refresh(scan)

    return ScanUploadResponse(
        scan_id=scan.id,
        total_findings=len(payload.vulnerabilities),
        scored=scored,
        skipped=skipped,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get a scan record."""
    return _scan_or_404(scan_id, db)


@router.get("/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
def get_scan_vulnerabilities(scan_id: int, db: Session = Depends(get_db)):
    """List all vulnerabilities for a specific scan, ordered by priority_score DESC."""
    _scan_or_404(scan_id, db)
    stmt = (
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.priority_score.desc().nullslast())
    )
    vulns = db.execute(stmt).scalars().all()
    return [_vuln_to_response(v) for v in vulns]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _vuln_to_response(v: Vulnerability) -> VulnerabilityResponse:
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
        explainability=None,
    )
