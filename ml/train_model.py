"""
train_model.py — Train GradientBoosting regressor pipeline for VAPT risk prioritization.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics import mean_squared_error, r2_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from generate_synthetic_data import generate

logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")
logger = logging.getLogger(__name__)

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"
DATA_PATH = Path(__file__).parent.parent / "data" / "synthetic_vapt_training.csv"

FEATURE_COLS = [
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


def train_and_save():
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    if not DATA_PATH.exists():
        logger.info("Dataset missing. Generating synthetic training data...")
        df = generate(n_samples=2500, output_path=DATA_PATH)
    else:
        logger.info("Loading training data from %s...", DATA_PATH)
        df = pd.read_csv(DATA_PATH)

    X = df[FEATURE_COLS]
    y_reg = df["priority_score"]

    X_train, X_test, y_reg_train, y_reg_test = train_test_split(
        X, y_reg, test_size=0.2, random_state=42
    )

    logger.info("Training Gradient Boosting Regressor (Priority Score 0-100)...")
    regressor = Pipeline([
        ("scaler", StandardScaler()),
        ("model", GradientBoostingRegressor(n_estimators=120, max_depth=4, learning_rate=0.08, random_state=42))
    ])
    regressor.fit(X_train, y_reg_train)

    reg_preds = regressor.predict(X_test)
    rmse = mean_squared_error(y_reg_test, reg_preds) ** 0.5
    r2 = r2_score(y_reg_test, reg_preds)

    # Compute classification proxy accuracy from regression predictions against test thresholds
    from scoring_weights import get_risk_tier
    actual_tiers = [get_risk_tier(s) for s in y_reg_test]
    pred_tiers = [get_risk_tier(s) for s in reg_preds]
    correct = sum(1 for a, p in zip(actual_tiers, pred_tiers) if a == p)
    test_accuracy = round(correct / len(actual_tiers), 4)

    logger.info("Test evaluation: RMSE = %.3f, R2 = %.4f, Tier Accuracy = %.2f%%", rmse, r2, test_accuracy * 100)

    # Feature importances
    gb_model = regressor.named_steps["model"]
    importances = {name: float(round(imp, 4)) for name, imp in zip(FEATURE_COLS, gb_model.feature_importances_)}
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    regressor._version = "1.0.0"

    reg_path = ARTIFACTS_DIR / "risk_regressor.pkl"
    features_path = ARTIFACTS_DIR / "feature_names.json"
    metadata_path = ARTIFACTS_DIR / "model_metadata.json"

    joblib.dump(regressor, reg_path)

    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(FEATURE_COLS, f, indent=2)

    metadata = {
        "version": "1.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_samples": len(df),
        "test_rmse": round(rmse, 3),
        "test_r2": round(r2, 4),
        "test_accuracy": test_accuracy,
        "feature_importances": sorted_importances,
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Exported model artifacts to %s", ARTIFACTS_DIR)


if __name__ == "__main__":
    train_and_save()
