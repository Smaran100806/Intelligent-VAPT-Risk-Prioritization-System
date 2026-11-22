"""
scoring_weights.py — Single source of truth for VAPT scoring weights and encoding maps.

Provides:
  - EXPOSURE_MAP, VULN_TYPE_MAP, ATTACK_VECTOR_MAP, RISK_TIER_THRESHOLDS
  - WEIGHTS, SCORE_MIN, SCORE_MAX
  - compute_heuristic_score, get_risk_tier
"""

from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Feature Encodings (String -> Integer)
# ---------------------------------------------------------------------------

EXPOSURE_MAP: Dict[str, int] = {
    "isolated": 0,
    "internal": 1,
    "dmz": 2,
    "internet-facing": 3,
}

VULN_TYPE_MAP: Dict[str, int] = {
    "other": 0,
    "xss": 1,
    "lfi": 2,
    "ssrf": 3,
    "sqli": 4,
    "rce": 5,
}

ATTACK_VECTOR_MAP: Dict[str, int] = {
    "physical": 0,
    "local": 1,
    "adjacent": 2,
    "network": 3,
}

RISK_TIER_THRESHOLDS: List[Tuple[float, str]] = [
    (75.0, "Critical"),
    (50.0, "High"),
    (25.0, "Medium"),
    (0.0,  "Low"),
]

# ---------------------------------------------------------------------------
# Feature Weight Multipliers
# ---------------------------------------------------------------------------

WEIGHTS = {
    "cvss_score": 3.8,
    "cvss_impact": 2.2,
    "asset_criticality": 4.5,
    "exposure_encoded": 5.2,
    "exploit_available": 10.0,
    "in_threat_feed": 8.5,
    "attack_vector_encoded": 2.5,
    "historical_recurrence": 1.8,
    "auth_required_penalty": 4.0,
    "scaling_factor": 0.95,
}

SCORE_MIN: float = 5.0
SCORE_MAX: float = 100.0


def compute_heuristic_score(
    cvss_score: float,
    cvss_impact: float,
    asset_criticality: int,
    exposure_encoded: int,
    exploit_available: int,
    in_threat_feed: int,
    attack_vector_encoded: int,
    historical_recurrence: int,
    auth_required: int,
) -> float:
    raw = (
        (cvss_score * WEIGHTS["cvss_score"])
        + (cvss_impact * WEIGHTS["cvss_impact"])
        + (asset_criticality * WEIGHTS["asset_criticality"])
        + (exposure_encoded * WEIGHTS["exposure_encoded"])
        + (exploit_available * WEIGHTS["exploit_available"])
        + (in_threat_feed * WEIGHTS["in_threat_feed"])
        + (attack_vector_encoded * WEIGHTS["attack_vector_encoded"])
        + (historical_recurrence * WEIGHTS["historical_recurrence"])
        - (auth_required * WEIGHTS["auth_required_penalty"])
    )
    score = raw * WEIGHTS["scaling_factor"]
    clipped = max(min(score, SCORE_MAX), SCORE_MIN)
    return round(float(clipped), 2)


def get_risk_tier(score: float) -> str:
    for threshold, tier in RISK_TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "Low"
