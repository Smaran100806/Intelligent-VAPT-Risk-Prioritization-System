"""
ml_service.py — ML inference service for vulnerability risk scoring.

If risk_regressor.pkl is missing or fails to load, scoring uses the heuristic
and responses say so via model_used / scoring_mode.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import pandas as pd

from app.scoring_weights import (
    ATTACK_VECTOR_MAP,
    EXPOSURE_MAP,
    VULN_TYPE_MAP,
    WEIGHTS,
    compute_heuristic_score,
    derive_cvss_subscores,
    encode_feature,
    get_risk_tier,
)

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_ARTIFACTS_DIR = Path(os.getenv("ML_ARTIFACTS_DIR", str(_PROJECT_ROOT / "ml" / "artifacts")))
_REGRESSOR_PATH = _ARTIFACTS_DIR / "risk_regressor.pkl"
_METADATA_PATH = _ARTIFACTS_DIR / "model_metadata.json"

FEATURE_NAMES = [
    "cvss_score",
    "cvss_exploitability",
    "cvss_impact",
    "asset_criticality",
    "exposure_encoded",
    "vuln_type_encoded",
    "exploit_available",
    "in_threat_feed",
    "auth_required",
    "attack_vector_encoded",
    "historical_recurrence",
    "days_since_last_scan",
]

_regressor = None
_models_attempted: bool = False

_METRIC_NOTE = (
    "test_tier_agreement is the share of held-out synthetic rows whose regression "
    "score falls in the same tier as the formula label. It is not classifier accuracy "
    "and it does not show that the model outperforms CVSS on observed breaches."
)


def _load_models() -> Any:
    global _regressor, _models_attempted
    if _models_attempted:
        return _regressor

    _models_attempted = True
    if not _REGRESSOR_PATH.exists():
        logger.warning(
            "Regressor artifact missing at %s. Scores will use the heuristic formula. "
            "Train and keep the file with: python ml/train_model.py",
            _REGRESSOR_PATH,
        )
        return None

    try:
        _regressor = joblib.load(_REGRESSOR_PATH)
        logger.info("Loaded regressor from %s", _REGRESSOR_PATH)
    except Exception as exc:
        logger.error("Failed loading regressor, using heuristic: %s", exc)
        _regressor = None

    return _regressor


def _build_feature_dict(vuln: Dict[str, Any], asset: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
    warnings: List[str] = []
    cvss = float(vuln.get("cvss_score") or 0.0)
    cvss_exploitability, cvss_impact = derive_cvss_subscores(cvss)
    asset_criticality = int(asset.get("criticality") or 3)

    exposure_encoded, exposure_warning = encode_feature(
        asset.get("exposure"), EXPOSURE_MAP, "internal", "exposure"
    )
    vuln_type_encoded, vuln_warning = encode_feature(
        vuln.get("vuln_type"), VULN_TYPE_MAP, "other", "vuln_type"
    )
    attack_vector_encoded, vector_warning = encode_feature(
        vuln.get("attack_vector"), ATTACK_VECTOR_MAP, "network", "attack_vector"
    )
    for warning in (exposure_warning, vuln_warning, vector_warning):
        if warning:
            warnings.append(warning)

    return {
        "cvss_score": cvss,
        "cvss_exploitability": cvss_exploitability,
        "cvss_impact": cvss_impact,
        "asset_criticality": asset_criticality,
        "exposure_encoded": exposure_encoded,
        "vuln_type_encoded": vuln_type_encoded,
        "exploit_available": 1 if vuln.get("exploit_available") else 0,
        "in_threat_feed": 1 if vuln.get("in_threat_feed") else 0,
        "auth_required": 1 if vuln.get("auth_required") else 0,
        "attack_vector_encoded": attack_vector_encoded,
        "historical_recurrence": int(vuln.get("historical_recurrence") or 0),
        "days_since_last_scan": int(vuln.get("days_since_last_scan") or 0),
    }, warnings


def _heuristic_from_features(features: Dict[str, Any]) -> float:
    return compute_heuristic_score(
        cvss_score=features["cvss_score"],
        cvss_impact=features["cvss_impact"],
        asset_criticality=features["asset_criticality"],
        exposure_encoded=features["exposure_encoded"],
        exploit_available=features["exploit_available"],
        in_threat_feed=features["in_threat_feed"],
        attack_vector_encoded=features["attack_vector_encoded"],
        historical_recurrence=features["historical_recurrence"],
        auth_required=features["auth_required"],
    )


def _build_explainability(features: Dict[str, Any], score: float, is_model: bool) -> Dict[str, Any]:
    """Return factor-contribution breakdown. Numeric keys are contributions; note and risk_tier are not."""
    note = (
        "Approximate heuristic breakdown — not the model's internal attribution"
        if is_model
        else "Heuristic formula breakdown"
    )
    return {
        "note": note,
        "cvss_contribution": round(features["cvss_score"] * WEIGHTS["cvss_score"], 2),
        "impact_contribution": round(features["cvss_impact"] * WEIGHTS["cvss_impact"], 2),
        "asset_criticality_contribution": round(features["asset_criticality"] * WEIGHTS["asset_criticality"], 2),
        "exposure_contribution": round(features["exposure_encoded"] * WEIGHTS["exposure_encoded"], 2),
        "exploit_available_contribution": round(features["exploit_available"] * WEIGHTS["exploit_available"], 2),
        "threat_feed_contribution": round(features["in_threat_feed"] * WEIGHTS["in_threat_feed"], 2),
        "attack_vector_contribution": round(features["attack_vector_encoded"] * WEIGHTS["attack_vector_encoded"], 2),
        "recurrence_contribution": round(features["historical_recurrence"] * WEIGHTS["historical_recurrence"], 2),
        "auth_penalty": round(-features["auth_required"] * WEIGHTS["auth_required_penalty"], 2),
        "total_score": score,
        "risk_tier": get_risk_tier(score),
    }


def explain_stored(
    vuln: Dict[str, Any],
    asset: Dict[str, Any],
    priority_score: float,
    model_used: Optional[str],
) -> Dict[str, Any]:
    """Explain a score that was already stored, without replacing it with a fresh prediction."""
    features, _warnings = _build_feature_dict(vuln, asset)
    return _build_explainability(
        features,
        float(priority_score or 0.0),
        is_model=(model_used == "regressor"),
    )


def score_vulnerability(vuln: Dict[str, Any], asset: Dict[str, Any]) -> Dict[str, Any]:
    """Score a single vulnerability using the regressor, or the heuristic when it is unavailable."""
    regressor = _load_models()
    features, warnings = _build_feature_dict(vuln, asset)

    if regressor is not None:
        try:
            df = pd.DataFrame([features], columns=FEATURE_NAMES)
            pred = float(regressor.predict(df)[0])
            priority_score = round(max(min(pred, 100.0), 0.0), 2)
            model_used = "regressor"
        except Exception as exc:
            logger.warning("Regressor error, using heuristic: %s", exc)
            priority_score = _heuristic_from_features(features)
            model_used = "heuristic"
            warnings.append("Regressor failed at inference; heuristic score was stored")
    else:
        priority_score = _heuristic_from_features(features)
        model_used = "heuristic"

    risk_tier = get_risk_tier(priority_score)
    explainability = _build_explainability(features, priority_score, is_model=(model_used == "regressor"))

    return {
        "priority_score": priority_score,
        "risk_tier": risk_tier,
        "explainability": explainability,
        "model_used": model_used,
        "warnings": warnings,
    }


def get_model_metadata() -> Dict[str, Any]:
    regressor = _load_models()
    meta: Dict[str, Any] = {}
    if _METADATA_PATH.exists():
        with open(_METADATA_PATH, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
            if isinstance(loaded, dict):
                meta = loaded

    model_loaded = regressor is not None
    agreement = meta.get("test_tier_agreement", meta.get("test_accuracy"))
    meta.update(
        {
            "model_loaded": model_loaded,
            "scoring_mode": "regressor" if model_loaded else "heuristic",
            "active_scorer": "regressor" if model_loaded else "heuristic",
            "label_source": meta.get("label_source", "synthetic_heuristic_plus_noise"),
            "metric_note": meta.get("metric_note", _METRIC_NOTE),
            "reported_tier_agreement": agreement if model_loaded else None,
        }
    )
    if not model_loaded:
        meta["fallback_reason"] = (
            "risk_regressor.pkl is not available. Scores use the heuristic formula. "
            "Run python ml/train_model.py and keep ml/artifacts/risk_regressor.pkl."
        )
        meta["test_tier_agreement"] = None
        meta["test_accuracy"] = None
        meta["test_rmse"] = None
        meta["test_r2"] = None
    return meta
