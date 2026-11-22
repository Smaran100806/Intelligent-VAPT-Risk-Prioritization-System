"""
ml_service.py — ML inference wrapper for the FastAPI backend.

Loads the trained risk-scoring model from disk and exposes a simple
`predict_risk_score()` function that the API routers call.

Model training lives in ml/train_model.py.
Artifact path is configured via ML_MODEL_PATH env variable.
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Optional

# joblib / pickle import is intentionally lazy to keep startup fast when model
# is not yet available (e.g., during CI or first-run setup).

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MODEL_PATH: Path = Path(
    os.getenv("ML_MODEL_PATH", "ml/artifacts/risk_model.pkl")
)

# ---------------------------------------------------------------------------
# Module-level model cache (loaded once at first inference call)
# ---------------------------------------------------------------------------

_model = None  # type: ignore[assignment]


def _load_model():
    """Load the trained model from disk into memory (lazy singleton)."""
    global _model

    if _model is not None:
        return _model

    if not MODEL_PATH.exists():
        logger.warning(
            "ML model artifact not found at '%s'. "
            "Run `python ml/train_model.py` to generate it. "
            "Returning placeholder scores until model is available.",
            MODEL_PATH,
        )
        return None

    try:
        import joblib
        _model = joblib.load(MODEL_PATH)
        logger.info("ML model loaded from '%s'.", MODEL_PATH)
    except Exception as exc:
        logger.error("Failed to load ML model: %s", exc)
        _model = None

    return _model


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def predict_risk_score(
    cvss_score: float,
    asset_criticality: int,
    exploitability_score: Optional[float] = None,
    threat_intel_boost: float = 0.0,
) -> dict:
    """
    Compute a composite risk score for a single vulnerability.

    Parameters
    ----------
    cvss_score          : CVSS base score (0.0 – 10.0)
    asset_criticality   : Asset criticality tier (1 – 5)
    exploitability_score: Optional standalone exploitability metric
    threat_intel_boost  : Additive boost from threat-intel feeds (0.0 – 1.0)

    Returns
    -------
    dict with keys:
        composite_score (float, 0–100),
        model_version   (str),
        fallback        (bool)
    """
    model = _load_model()

    if model is None:
        # Fallback heuristic when model artifact is absent
        base = (cvss_score / 10.0) * 60
        criticality_weight = (asset_criticality / 5.0) * 30
        composite = round(min(base + criticality_weight + threat_intel_boost * 10, 100), 2)
        return {
            "composite_score": composite,
            "model_version": "heuristic-fallback",
            "fallback": True,
        }

    # TODO: build feature vector matching training schema and call model.predict()
    # features = _build_feature_vector(cvss_score, asset_criticality, ...)
    # composite = float(model.predict_proba([features])[0][1]) * 100

    return {
        "composite_score": 0.0,
        "model_version": getattr(model, "_version", "unknown"),
        "fallback": False,
    }


def get_model_info() -> dict:
    """Return metadata about the currently loaded model."""
    model = _load_model()
    if model is None:
        return {"status": "not_loaded", "path": str(MODEL_PATH)}
    return {
        "status": "loaded",
        "path": str(MODEL_PATH),
        "version": getattr(model, "_version", "unknown"),
        "type": type(model).__name__,
    }
