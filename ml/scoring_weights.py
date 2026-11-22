"""
scoring_weights.py — Import shim.

Canonical constants live in backend/app/scoring_weights.py. This module loads
that file by path so training scripts can `from scoring_weights import ...`
from any working directory without keeping a second copy of the weights.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_CANONICAL = Path(__file__).resolve().parents[1] / "backend" / "app" / "scoring_weights.py"
_SPEC = importlib.util.spec_from_file_location("vapt_scoring_weights", _CANONICAL)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"Cannot load scoring weights from {_CANONICAL}")

_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

WEIGHTS = _MODULE.WEIGHTS
SCORE_MIN = _MODULE.SCORE_MIN
SCORE_MAX = _MODULE.SCORE_MAX
EXPOSURE_MAP = _MODULE.EXPOSURE_MAP
VULN_TYPE_MAP = _MODULE.VULN_TYPE_MAP
ATTACK_VECTOR_MAP = _MODULE.ATTACK_VECTOR_MAP
RISK_TIER_THRESHOLDS = _MODULE.RISK_TIER_THRESHOLDS
CVSS_EXPLOITABILITY_FACTOR = _MODULE.CVSS_EXPLOITABILITY_FACTOR
CVSS_IMPACT_FACTOR = _MODULE.CVSS_IMPACT_FACTOR
compute_heuristic_score = _MODULE.compute_heuristic_score
derive_cvss_subscores = _MODULE.derive_cvss_subscores
encode_feature = _MODULE.encode_feature
get_risk_tier = _MODULE.get_risk_tier
