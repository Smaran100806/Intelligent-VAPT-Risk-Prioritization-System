"""
evaluate.py — Evaluate the trained risk prioritization model.

Metrics reported:
  - Accuracy, Precision, Recall, F1-score (classification)
  - ROC-AUC
  - Confusion matrix
  - Feature importance plot (optional)

Usage:
    python ml/evaluate.py --model ml/artifacts/risk_model.pkl --data data/test_set.csv

Full implementation to be added in the ML milestone.
"""

import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")
logger = logging.getLogger(__name__)


def load_model(model_path: Path):
    """Load model artifact. TODO: implement."""
    raise NotImplementedError("load_model() — to be implemented in ML milestone")


def load_test_data(data_path: Path):
    """Load held-out test set. TODO: implement."""
    raise NotImplementedError("load_test_data() — to be implemented in ML milestone")


def evaluate(model, X_test, y_test) -> dict:
    """Compute and return evaluation metrics. TODO: implement."""
    raise NotImplementedError("evaluate() — to be implemented in ML milestone")


def print_report(metrics: dict) -> None:
    """Pretty-print the evaluation report. TODO: implement."""
    raise NotImplementedError("print_report() — to be implemented in ML milestone")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate VAPT risk model")
    parser.add_argument("--model", type=Path, default=Path("ml/artifacts/risk_model.pkl"))
    parser.add_argument("--data",  type=Path, default=Path("data/test_set.csv"))
    args = parser.parse_args()

    logger.info("evaluate.py — placeholder. Full evaluation logic coming in ML milestone.")
