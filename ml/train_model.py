"""
train_model.py — Train GradientBoosting models for VAPT risk prioritization.

Outputs:
  - ml/artifacts/risk_regressor.pkl
  - ml/artifacts/risk_classifier.pkl
  - ml/artifacts/feature_names.json
  - ml/artifacts/model_metadata.json
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingRegressor, GradientBoostingClassifier
from sklearn.metrics import mean_squared_error, r2_score, accuracy_score, classification_report
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
        logger.info(f"Loading training data from {DATA_PATH}...")
        df = pd.read_csv(DATA_PATH)

    X = df[FEATURE_COLS]
    y_reg = df["priority_score"]
    y_cls = df["risk_tier"]

    X_train, X_test, y_reg_train, y_reg_test, y_cls_train, y_cls_test = train_test_split(
        X, y_reg, y_cls, test_size=0.2, random_state=42
    )

    logger.info("Training Gradient Boosting Regressor (Priority Score 0-100)...")
    regressor = Pipeline([
        ("scaler", StandardScaler()),
        ("model", GradientBoostingRegressor(n_estimators=120, max_depth=4, learning_rate=0.08, random_state=42))
    ])
    regressor.fit(X_train, y_reg_train)
    reg_preds = regressor.predict(X_test)
    mse = mean_squared_error(y_reg_test, reg_preds)
    r2 = r2_score(y_reg_test, reg_preds)
    logger.info(f"Regressor performance: RMSE = {mse**0.5:.2f}, R2 = {r2:.4f}")

    logger.info("Training Gradient Boosting Classifier (Risk Tier)...")
    classifier = Pipeline([
        ("scaler", StandardScaler()),
        ("model", GradientBoostingClassifier(n_estimators=100, max_depth=3, learning_rate=0.1, random_state=42))
    ])
    classifier.fit(X_train, y_cls_train)
    cls_preds = classifier.predict(X_test)
    acc = accuracy_score(y_cls_test, cls_preds)
    logger.info(f"Classifier Accuracy = {acc * 100:.2f}%")
    logger.info("\n" + classification_report(y_cls_test, cls_preds))

    # Extract feature importances from regressor
    gb_model = regressor.named_steps["model"]
    importances = {name: float(round(imp, 4)) for name, imp in zip(FEATURE_COLS, gb_model.feature_importances_)}
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    # Set version attributes
    regressor._version = "1.0.0"
    classifier._version = "1.0.0"

    # Save artifacts
    reg_path = ARTIFACTS_DIR / "risk_regressor.pkl"
    cls_path = ARTIFACTS_DIR / "risk_classifier.pkl"
    features_path = ARTIFACTS_DIR / "feature_names.json"
    metadata_path = ARTIFACTS_DIR / "model_metadata.json"

    joblib.dump(regressor, reg_path)
    joblib.dump(classifier, cls_path)

    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(FEATURE_COLS, f, indent=2)

    metadata = {
        "version": "1.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_samples": len(df),
        "test_rmse": round(mse**0.5, 3),
        "test_r2": round(r2, 4),
        "test_accuracy": round(acc, 4),
        "feature_importances": sorted_importances,
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Successfully exported ML models and metadata to ml/artifacts/")
    logger.info(f"Top 5 Influential Features:\n{json.dumps(dict(list(sorted_importances.items())[:5]), indent=2)}")

if __name__ == "__main__":
    train_and_save()
