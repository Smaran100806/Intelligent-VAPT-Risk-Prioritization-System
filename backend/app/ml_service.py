"""
ml_service.py — ML inference service for vulnerability risk scoring.

Feature vector matches the training schema:
  [cvss_score, cvss_exploitability, cvss_impact, asset_criticality,
   exposure_encoded, vuln_type_encoded, exploit_available, in_threat_feed,
   auth_required, attack_vector_encoded, historical_recurrence, days_since_last_scan]

Lazy-loads risk_regressor.pkl and risk_classifier.pkl from ml/artifacts/.
Falls back to a heuristic formula when model artifacts are absent.
"""

from __future__ import annotations

import logging
import os
import warnings
from pathlib import Path
from typing import Any, Dict, Optional
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Artifact paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_ARTIFACTS_DIR = Path(os.getenv("ML_ARTIFACTS_DIR", str(_PROJECT_ROOT / "ml" / "artifacts")))
_REGRESSOR_PATH = _ARTIFACTS_DIR / "risk_regressor.pkl"
_CLASSIFIER_PATH = _ARTIFACTS_DIR / "risk_classifier.pkl"

# ---------------------------------------------------------------------------
# Encoding maps  (string -> int)  — must match training label encoding
# ---------------------------------------------------------------------------

EXPOSURE_MAP: Dict[str, int] = {
    "internet-facing": 3,
    "dmz": 2,
    "internal": 1,
    "isolated": 0,
}

VULN_TYPE_MAP: Dict[str, int] = {
    "rce": 5,
    "sqli": 4,
    "ssrf": 3,
    "lfi": 2,
    "xss": 1,
    "other": 0,
}

ATTACK_VECTOR_MAP: Dict[str, int] = {
    "network": 3,
    "adjacent": 2,
    "local": 1,
    "physical": 0,
}

RISK_TIER_THRESHOLDS = [
    (75.0, "Critical"),
    (50.0, "High"),
    (25.0, "Medium"),
    (0.0, "Low"),
]

# ---------------------------------------------------------------------------
# Lazy model cache
# ---------------------------------------------------------------------------

_regressor = None
_classifier = None
_models_attempted = False


def _load_models() -> tuple:
    """Load models from disk once; return (regressor, classifier) or (None, None)."""
    global _regressor, _classifier, _models_attempted

    if _models_attempted:
        return _regressor, _classifier

    _models_attempted = True

    try:
        import joblib  # noqa: PLC0415

        if _REGRESSOR_PATH.exists():
            _regressor = joblib.load(_REGRESSOR_PATH)
            logger.info("Loaded regressor from %s", _REGRESSOR_PATH)
        else:
            logger.warning("Regressor artifact not found at %s — using heuristic fallback.", _REGRESSOR_PATH)

        if _CLASSIFIER_PATH.exists():
            _classifier = joblib.load(_CLASSIFIER_PATH)
            logger.info("Loaded classifier from %s", _CLASSIFIER_PATH)
        else:
            logger.warning("Classifier artifact not found at %s — using heuristic fallback.", _CLASSIFIER_PATH)

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load ML models: %s", exc)
        _regressor = None
        _classifier = None

    return _regressor, _classifier


# ---------------------------------------------------------------------------
# Feature building
# ---------------------------------------------------------------------------

def _build_feature_vector(vuln: Dict[str, Any], asset: Dict[str, Any]) -> list:
    """
    Build the 12-element feature vector in training order:
      [cvss_score, cvss_exploitability, cvss_impact, asset_criticality,
       exposure_encoded, vuln_type_encoded, exploit_available, in_threat_feed,
       auth_required, attack_vector_encoded, historical_recurrence, days_since_last_scan]
    """
    cvss_score = float(vuln.get("cvss_score") or 0.0)

    # Derive exploitability/impact from CVSS score using rough proportions
    cvss_exploitability = round(cvss_score * 0.4, 2)   # ~40 % of CVSS is exploitability
    cvss_impact = round(cvss_score * 0.6, 2)            # ~60 % is impact

    asset_criticality = int(asset.get("criticality") or 3)

    exposure_raw = str(asset.get("exposure") or "internal").lower()
    exposure_encoded = EXPOSURE_MAP.get(exposure_raw, 1)

    vuln_type_raw = str(vuln.get("vuln_type") or "other").lower()
    vuln_type_encoded = VULN_TYPE_MAP.get(vuln_type_raw, 0)

    exploit_available = int(bool(vuln.get("exploit_available", False)))
    in_threat_feed = int(bool(vuln.get("in_threat_feed", False)))
    auth_required = int(bool(vuln.get("auth_required", False)))

    attack_vector_raw = str(vuln.get("attack_vector") or "network").lower()
    attack_vector_encoded = ATTACK_VECTOR_MAP.get(attack_vector_raw, 3)

    historical_recurrence = int(vuln.get("historical_recurrence") or 0)
    days_since_last_scan = int(vuln.get("days_since_last_scan") or 0)

    return [
        cvss_score,
        cvss_exploitability,
        cvss_impact,
        asset_criticality,
        exposure_encoded,
        vuln_type_encoded,
        exploit_available,
        in_threat_feed,
        auth_required,
        attack_vector_encoded,
        historical_recurrence,
        days_since_last_scan,
    ]


def _heuristic_score(vuln: Dict[str, Any], asset: Dict[str, Any]) -> float:
    """
    Fallback heuristic that mirrors the formula used in generate_synthetic_data.py.
    Returns a priority score in [0, 100].
    """
    cvss = float(vuln.get("cvss_score") or 0.0)
    criticality = int(asset.get("criticality") or 3)
    exposure_raw = str(asset.get("exposure") or "internal").lower()
    exposure_weight = EXPOSURE_MAP.get(exposure_raw, 1) / 3.0  # normalise to [0,1]

    exploit = 1.0 if vuln.get("exploit_available") else 0.0
    threat_feed = 1.0 if vuln.get("in_threat_feed") else 0.0
    recurrence = min(int(vuln.get("historical_recurrence") or 0), 10) / 10.0
    staleness = min(int(vuln.get("days_since_last_scan") or 0), 365) / 365.0
    auth_penalty = -0.5 if vuln.get("auth_required") else 0.0

    score = (
        cvss * 4.5
        + criticality * 4.0
        + exposure_weight * 10.0
        + exploit * 15.0
        + threat_feed * 10.0
        + recurrence * 5.0
        + staleness * 3.0
        + auth_penalty
    )
    return round(min(max(score, 0.0), 100.0), 2)


def _tier_from_score(score: float) -> str:
    for threshold, tier in RISK_TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "Low"


def _build_explainability(vuln: Dict[str, Any], asset: Dict[str, Any], score: float) -> Dict[str, Any]:
    """Return a factor-contribution breakdown for transparency."""
    cvss = float(vuln.get("cvss_score") or 0.0)
    criticality = int(asset.get("criticality") or 3)
    exposure_raw = str(asset.get("exposure") or "internal").lower()
    exposure_weight = EXPOSURE_MAP.get(exposure_raw, 1) / 3.0

    exploit = 1.0 if vuln.get("exploit_available") else 0.0
    threat_feed = 1.0 if vuln.get("in_threat_feed") else 0.0
    recurrence = min(int(vuln.get("historical_recurrence") or 0), 10) / 10.0
    staleness = min(int(vuln.get("days_since_last_scan") or 0), 365) / 365.0

    factors = {
        "cvss_contribution": round(cvss * 4.5, 2),
        "asset_criticality_contribution": round(criticality * 4.0, 2),
        "exposure_contribution": round(exposure_weight * 10.0, 2),
        "exploit_available_contribution": round(exploit * 15.0, 2),
        "threat_feed_contribution": round(threat_feed * 10.0, 2),
        "recurrence_contribution": round(recurrence * 5.0, 2),
        "staleness_contribution": round(staleness * 3.0, 2),
        "auth_required_penalty": round((-0.5 if vuln.get("auth_required") else 0.0), 2),
    }
    factors["total_score"] = score
    factors["risk_tier"] = _tier_from_score(score)
    return factors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_vulnerability(vuln: Dict[str, Any], asset: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score a single vulnerability.

    Parameters
    ----------
    vuln  : dict with vulnerability fields (cvss_score, exploit_available, …)
    asset : dict with asset fields (criticality, exposure, …)

    Returns
    -------
    {
        "priority_score": float,       # 0–100
        "risk_tier": str,              # Critical | High | Medium | Low
        "explainability": dict,        # factor breakdown
        "model_used": str,             # "regressor" | "heuristic"
    }
    """
    regressor, _classifier = _load_models()

    if regressor is not None:
        try:
            features = _build_feature_vector(vuln, asset)
            feature_names = [
                "cvss_score", "cvss_exploitability", "cvss_impact", "asset_criticality",
                "exposure_encoded", "vuln_type_encoded", "exploit_available", "in_threat_feed",
                "auth_required", "attack_vector_encoded", "historical_recurrence", "days_since_last_scan"
            ]
            features_df = pd.DataFrame([features], columns=feature_names)
            priority_score = float(regressor.predict(features_df)[0])
            priority_score = round(min(max(priority_score, 0.0), 100.0), 2)
            model_used = "regressor"
        except Exception as exc:  # noqa: BLE001
            logger.warning("Regressor prediction failed (%s), using heuristic.", exc)
            priority_score = _heuristic_score(vuln, asset)
            model_used = "heuristic"
    else:
        priority_score = _heuristic_score(vuln, asset)
        model_used = "heuristic"

    risk_tier = _tier_from_score(priority_score)
    explainability = _build_explainability(vuln, asset, priority_score)
    explainability["model_used"] = model_used

    return {
        "priority_score": priority_score,
        "risk_tier": risk_tier,
        "explainability": explainability,
        "model_used": model_used,
    }
