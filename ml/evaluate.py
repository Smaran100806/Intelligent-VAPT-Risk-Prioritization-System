"""
evaluate.py — Evaluate the trained VAPT risk model and compare ML vs CVSS-only sorting.
"""

import json
import logging
from pathlib import Path
import joblib
import pandas as pd
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score, accuracy_score, classification_report

logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")
logger = logging.getLogger(__name__)

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"
DATA_PATH = Path(__file__).parent.parent / "data" / "synthetic_vapt_training.csv"

def evaluate_models():
    reg_path = ARTIFACTS_DIR / "risk_regressor.pkl"
    cls_path = ARTIFACTS_DIR / "risk_classifier.pkl"

    if not reg_path.exists() or not cls_path.exists():
        logger.error("Model artifacts not found. Please run ml/train_model.py first.")
        return

    logger.info("Loading model pipelines...")
    regressor = joblib.load(reg_path)
    classifier = joblib.load(cls_path)

    df = pd.read_csv(DATA_PATH)
    with open(ARTIFACTS_DIR / "feature_names.json", "r") as f:
        feature_cols = json.load(f)

    X = df[feature_cols]
    y_reg = df["priority_score"]
    y_cls = df["risk_tier"]

    # 1. Regression Metrics
    preds_reg = regressor.predict(X)
    rmse = mean_squared_error(y_reg, preds_reg) ** 0.5
    mae = mean_absolute_error(y_reg, preds_reg)
    r2 = r2_score(y_reg, preds_reg)

    # 2. Classification Metrics
    preds_cls = classifier.predict(X)
    acc = accuracy_score(y_cls, preds_cls)

    print("\n" + "="*60)
    print("      INTELLIGENT VAPT RISK MODEL EVALUATION REPORT")
    print("="*60)
    print(f"Total Samples Evaluated: {len(df)}")
    print(f"Regression RMSE       : {rmse:.3f}")
    print(f"Regression MAE        : {mae:.3f}")
    print(f"Regression R² Score   : {r2:.4f}")
    print(f"Classifier Accuracy   : {acc*100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_cls, preds_cls))

    # 3. Side-by-side CVSS vs ML comparison demonstration on 10 realistic samples
    sample_df = df.sample(10, random_state=101).copy()
    sample_df["predicted_ml_score"] = regressor.predict(sample_df[feature_cols]).round(1)
    
    cvss_ranked = sample_df.sort_values(by="cvss_score", ascending=False).reset_index(drop=True)
    cvss_ranked["cvss_rank"] = cvss_ranked.index + 1
    
    ml_ranked = cvss_ranked.sort_values(by="predicted_ml_score", ascending=False).reset_index(drop=True)
    ml_ranked["ml_rank"] = ml_ranked.index + 1
    ml_ranked["rank_delta"] = ml_ranked["cvss_rank"] - ml_ranked["ml_rank"]

    print("\n" + "="*80)
    print("DEMO: STATIC CVSS VS CONTEXT-AWARE ML RANK RE-ORDERING")
    print("="*80)
    comparison_view = ml_ranked[[
        "cvss_rank", "ml_rank", "rank_delta", "cvss_score", "predicted_ml_score",
        "asset_criticality", "exposure_encoded", "exploit_available"
    ]]
    print(comparison_view.to_string(index=False))
    print("\nNote: Positive rank_delta indicates ML escalated the vulnerability above its CVSS rank.")

    # Save evaluation summary
    report = {
        "rmse": round(rmse, 3),
        "mae": round(mae, 3),
        "r2": round(r2, 4),
        "accuracy": round(acc, 4),
    }
    with open(ARTIFACTS_DIR / "evaluation_report.json", "w") as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    evaluate_models()
