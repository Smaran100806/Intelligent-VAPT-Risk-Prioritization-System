"""
routers/comparison.py — CVSS vs ML ranking comparison endpoint.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan, Vulnerability
from app.schemas import ComparisonResponse, ComparisonRow

router = APIRouter()


@router.get("/cvss-vs-ml", response_model=ComparisonResponse)
def cvss_vs_ml_comparison(db: Session = Depends(get_db)):
    """
    Compare CVSS-based ranking with ML priority_score ranking for the
    most recent scan's findings.

    Returns each finding's rank in both orderings plus a delta that
    highlights promotions (ML ranks it more urgent) or demotions.
    """
    # Identify the most recent scan
    last_scan_stmt = select(Scan).order_by(Scan.scan_date.desc()).limit(1)
    last_scan = db.execute(last_scan_stmt).scalar_one_or_none()

    if last_scan is None:
        return ComparisonResponse(
            rows=[],
            total=0,
            promoted_count=0,
            demoted_count=0,
            unchanged_count=0,
        )

    # Fetch all non-remediated findings for that scan that have scores
    stmt = select(Vulnerability).where(
        Vulnerability.scan_id == last_scan.id,
        Vulnerability.is_remediated == False,  # noqa: E712
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

    # Sort by CVSS desc → rank
    cvss_sorted = sorted(vulns, key=lambda v: (v.cvss_score or 0.0), reverse=True)
    cvss_rank_map = {v.id: idx + 1 for idx, v in enumerate(cvss_sorted)}

    # Sort by ML priority_score desc → rank
    ml_sorted = sorted(vulns, key=lambda v: (v.priority_score or 0.0), reverse=True)
    ml_rank_map = {v.id: idx + 1 for idx, v in enumerate(ml_sorted)}

    rows: list[ComparisonRow] = []
    promoted = 0
    demoted = 0
    unchanged = 0

    for v in cvss_sorted:
        cvss_rank = cvss_rank_map[v.id]
        ml_rank = ml_rank_map[v.id]
        delta = ml_rank - cvss_rank  # negative = ML promotes it higher

        if delta < 0:
            promoted += 1
            reason = (
                f"ML promotes this finding {abs(delta)} position(s) higher than CVSS alone "
                f"due to contextual factors (asset criticality, exploit availability, threat feeds)."
            )
        elif delta > 0:
            demoted += 1
            reason = (
                f"ML de-prioritises this finding {delta} position(s) lower than CVSS suggests "
                f"(e.g. low asset criticality, no active exploit, isolated exposure)."
            )
        else:
            unchanged += 1
            reason = "ML ranking agrees with CVSS ranking for this finding."

        rows.append(
            ComparisonRow(
                vuln_id=v.id,
                title=v.title,
                cvss_score=v.cvss_score or 0.0,
                cvss_rank=cvss_rank,
                ml_score=v.priority_score or 0.0,
                ml_rank=ml_rank,
                delta=delta,
                reason=reason,
            )
        )

    # Return rows ordered by ML rank for the UI
    rows.sort(key=lambda r: r.ml_rank)

    return ComparisonResponse(
        rows=rows,
        total=len(rows),
        promoted_count=promoted,
        demoted_count=demoted,
        unchanged_count=unchanged,
    )
