"""
routers/dashboard.py — Dashboard statistics endpoint.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Vulnerability
from app.schemas import DashboardStats, VulnerabilityResponse

router = APIRouter()


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


@router.get("", response_model=DashboardStats)
def get_dashboard(db: Session = Depends(get_db)):
    """
    Aggregate statistics across all vulnerabilities for the dashboard.
    """
    all_vulns = db.execute(select(Vulnerability)).scalars().all()

    total_vulns = len(all_vulns)
    critical_count = sum(1 for v in all_vulns if v.severity == "critical")
    high_count = sum(1 for v in all_vulns if v.severity == "high")
    medium_count = sum(1 for v in all_vulns if v.severity == "medium")
    low_count = sum(1 for v in all_vulns if v.severity in ("low", "informational"))
    remediated_count = sum(1 for v in all_vulns if v.is_remediated)

    # Noise deprioritisation: medium/low vulns with priority_score < 30
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

    # Top 5 by priority_score
    top_risks_stmt = (
        select(Vulnerability)
        .where(Vulnerability.is_remediated == False)  # noqa: E712
        .order_by(Vulnerability.priority_score.desc().nullslast())
        .limit(5)
    )
    top_risks = db.execute(top_risks_stmt).scalars().all()

    severity_distribution = {
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
    }

    # Risk tier distribution
    risk_tier_counts: dict[str, int] = {}
    for v in all_vulns:
        tier = v.risk_tier or "Unscored"
        risk_tier_counts[tier] = risk_tier_counts.get(tier, 0) + 1

    return DashboardStats(
        total_vulns=total_vulns,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        remediated_count=remediated_count,
        noise_deprioritized_pct=noise_deprioritized_pct,
        top_risks=[_vuln_to_response(v) for v in top_risks],
        severity_distribution=severity_distribution,
        risk_tier_distribution=risk_tier_counts,
    )
