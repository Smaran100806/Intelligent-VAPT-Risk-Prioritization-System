"""
routers/dashboard.py — Dashboard statistics endpoint.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Vulnerability
from app.routers.helpers import vuln_to_response
from app.schemas import DashboardStats

router = APIRouter()


@router.get("", response_model=DashboardStats)
def get_dashboard(db: Session = Depends(get_db)):
    """Aggregate statistics across all vulnerabilities."""
    all_vulns = db.execute(select(Vulnerability)).scalars().all()

    total_vulns = len(all_vulns)
    critical_count = sum(1 for v in all_vulns if v.severity == "critical")
    high_count = sum(1 for v in all_vulns if v.severity == "high")
    medium_count = sum(1 for v in all_vulns if v.severity == "medium")
    low_count = sum(1 for v in all_vulns if v.severity in ("low", "informational"))

    critical_tier_count = sum(1 for v in all_vulns if v.risk_tier == "Critical")
    high_tier_count = sum(1 for v in all_vulns if v.risk_tier == "High")
    medium_tier_count = sum(1 for v in all_vulns if v.risk_tier == "Medium")
    low_tier_count = sum(1 for v in all_vulns if v.risk_tier == "Low")

    remediated_count = sum(1 for v in all_vulns if v.is_remediated)

    noise_candidates = [
        v for v in all_vulns
        if v.severity in ("medium", "low", "informational")
        and v.priority_score is not None
    ]
    noise_deprioritized = sum(1 for v in noise_candidates if (v.priority_score or 0.0) < 30.0)
    noise_deprioritized_pct = (
        round(noise_deprioritized / len(noise_candidates) * 100, 1)
        if noise_candidates
        else 0.0
    )

    top_risks_stmt = (
        select(Vulnerability)
        .where(Vulnerability.is_remediated == False)
        .order_by(Vulnerability.priority_score.desc().nullslast(), Vulnerability.id.asc())
        .limit(5)
    )
    top_vulns = db.execute(top_risks_stmt).scalars().all()
    top_risks = [vuln_to_response(v, include_explainability=False) for v in top_vulns]

    return DashboardStats(
        total_vulns=total_vulns,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        critical_tier_count=critical_tier_count,
        high_tier_count=high_tier_count,
        medium_tier_count=medium_tier_count,
        low_tier_count=low_tier_count,
        remediated_count=remediated_count,
        noise_deprioritized_pct=noise_deprioritized_pct,
        top_risks=top_risks,
        severity_distribution={
            "Critical": critical_count,
            "High": high_count,
            "Medium": medium_count,
            "Low": low_count,
        },
        risk_tier_distribution={
            "Critical": critical_tier_count,
            "High": high_tier_count,
            "Medium": medium_tier_count,
            "Low": low_tier_count,
        },
    )
