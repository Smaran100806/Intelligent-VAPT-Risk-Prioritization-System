"""
evaluate.py — Evaluate the trained VAPT risk model strictly on held-out test split.
"""

import json
import logging
from pathlib import Path
import joblib
import pandas as pd
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score, accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from scoring_weights import get_risk_tier

logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")
logger = logging.getLogger(__name__)

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"
DATA_PATH = Path(__file__).parent.parent / "data" / "synthetic_vapt_training.csv"


def evaluate_models():
    reg_path = ARTIFACTS_DIR / "risk_regressor.pkl"
    if not reg_path.exists():
        logger.error("Model artifact not found at %s. Please run ml/train_model.py first.", reg_path)
        return

    logger.info("Loading model regressor...")
    regressor = joblib.load(reg_path)

    df = pd.read_csv(DATA_PATH)
    with open(ARTIFACTS_DIR / "feature_names.json", "r") as f:
        feature_cols = json.load(f)

    X = df[feature_cols]
    y_reg = df["priority_score"]

    # Strictly evaluate on held-out 20% test split with random_state=42
    _, X_test, _, y_test = train_test_split(X, y_reg, test_size=0.2, random_state=42)

    preds_reg = regressor.predict(X_test)
    rmse = mean_squared_error(y_test, preds_reg) ** 0.5
    mae = mean_absolute_error(y_test, preds_reg)
    r2 = r2_score(y_test, preds_reg)

    actual_tiers = [get_risk_tier(s) for s in y_test]
    pred_tiers = [get_risk_tier(s) for s in preds_reg]
    acc = accuracy_score(actual_tiers, pred_tiers)

    print("\n" + "="*60)
    print("      INTELLIGENT VAPT RISK MODEL EVALUATION REPORT (TEST SPLIT)")
    print("="*60)
    print(f"Test Samples Evaluated: {len(X_test)}")
    print(f"Regression RMSE       : {rmse:.3f}")
    print(f"Regression MAE        : {mae:.3f}")
    print(f"Regression R² Score   : {r2:.4f}")
    print(f"Risk Tier Accuracy    : {acc*100:.2f}%")
    print("\nClassification Report (Risk Tiers):")
    print(classification_report(actual_tiers, pred_tiers))

    report = {
        "test_rmse": round(rmse, 3),
        "test_mae": round(mae, 3),
        "test_r2": round(r2, 4),
        "test_accuracy": round(acc, 4),
        "n_test_samples": len(X_test),
    }

    report_path = ARTIFACTS_DIR / "evaluation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info("Written test evaluation metrics -> %s", report_path)


if __name__ == "__main__":
    evaluate_models()
