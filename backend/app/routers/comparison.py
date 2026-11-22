"""
routers/comparison.py — CVSS vs ML ranking comparison and feature importance endpoints.
"""

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.ml_service import get_model_metadata
from app.models import Scan, Vulnerability
from app.schemas import ComparisonResponse, ComparisonRow, FeatureImportanceItem

router = APIRouter()


@router.get("/cvss-vs-ml", response_model=ComparisonResponse)
def cvss_vs_ml_comparison(db: Session = Depends(get_db)):
    """
    Compare CVSS ranking with ML priority_score ranking for the most recent scan.
    Breaks ties deterministically using vuln_id.
    """
    last_scan_stmt = select(Scan).order_by(Scan.scan_date.desc(), Scan.id.desc()).limit(1)
    last_scan = db.execute(last_scan_stmt).scalar_one_or_none()

    if last_scan is None:
        return ComparisonResponse(
            rows=[],
            total=0,
            promoted_count=0,
            demoted_count=0,
            unchanged_count=0,
        )

    stmt = select(Vulnerability).where(
        Vulnerability.scan_id == last_scan.id,
        Vulnerability.is_remediated == False,
    )
    vulns = db.execute(stmt).scalars().all()

    if not vulns:
        return ComparisonResponse(
            rows=[],
            total=0,
            promoted_count=0,
            demoted_count=0,
            unchanged_count=0,
        )

    # Sort ties deterministically by primary score desc, vuln.id asc
    cvss_sorted = sorted(
        vulns,
        key=lambda v: (-(v.cvss_score or 0.0), v.id),
    )
    cvss_rank_map = {v.id: idx + 1 for idx, v in enumerate(cvss_sorted)}

    ml_sorted = sorted(
        vulns,
        key=lambda v: (-(v.priority_score or 0.0), v.id),
    )
    ml_rank_map = {v.id: idx + 1 for idx, v in enumerate(ml_sorted)}

    rows: List[ComparisonRow] = []
    promoted = 0
    demoted = 0
    unchanged = 0

    for v in ml_sorted:
        cvss_rank = cvss_rank_map[v.id]
        ml_rank = ml_rank_map[v.id]
        delta = cvss_rank - ml_rank  # positive = ML escalated higher

        reasons = []
        asset = v.asset
        exposure = asset.exposure if asset else "internal"
        criticality = asset.criticality if asset else 3

        if exposure == "internet-facing":
            reasons.append("Internet-facing perimeter")
        elif exposure == "isolated":
            reasons.append("Isolated sandbox")

        if criticality >= 4:
            reasons.append(f"Mission-critical tier ({criticality}/5)")
        elif criticality <= 2:
            reasons.append("Low-criticality asset")

        if v.exploit_available:
            reasons.append("Public weaponized exploit")
        if v.in_threat_feed:
            reasons.append("Active threat intel signal")
        if v.auth_required:
            reasons.append("Auth barrier required")

        reason_text = " • ".join(reasons) if reasons else "Balanced contextual baseline"

        if delta > 0:
            promoted += 1
        elif delta < 0:
            demoted += 1
        else:
            unchanged += 1

        rows.append(
            ComparisonRow(
                vuln_id=v.id,
                title=v.title,
                asset_name=asset.name if asset else "Unassigned",
                risk_tier=v.risk_tier or "Medium",
                cvss_score=float(v.cvss_score or 0.0),
                cvss_rank=cvss_rank,
                ml_score=float(v.priority_score or 0.0),
                ml_rank=ml_rank,
                delta=delta,
                reason=reason_text,
            )
        )

    return ComparisonResponse(
        rows=rows,
        total=len(rows),
        promoted_count=promoted,
        demoted_count=demoted,
        unchanged_count=unchanged,
    )


@router.get("/feature-importance", response_model=List[FeatureImportanceItem])
def get_feature_importance():
    """Returns global feature importances sorted descending."""
    metadata = get_model_metadata()
    importances = metadata.get("feature_importances", {})
    sorted_items = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    return [FeatureImportanceItem(feature=k, importance=float(v)) for k, v in sorted_items]
