"""
routers/helpers.py — Shared response mapping helpers.
"""

from __future__ import annotations

from typing import Optional

from app.models import Vulnerability
from app.schemas import VulnerabilityResponse
from app.ml_service import score_vulnerability


def vuln_to_response(v: Vulnerability, include_explainability: bool = False) -> VulnerabilityResponse:
    asset = v.asset
    explainability = None
    if include_explainability:
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
            ml_eval = score_vulnerability(vuln_dict, asset_dict)
            explainability = ml_eval.get("explainability")
        except Exception:
            explainability = None

    return VulnerabilityResponse(
        id=v.id,
        scan_id=v.scan_id,
        asset_id=v.asset_id,
        asset_name=asset.name if asset else "Unassigned Target",
        asset_criticality=asset.criticality if asset else 3,
        asset_exposure=asset.exposure if asset else "internal",
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
