"""
generate_synthetic_data.py — Generate synthetic VAPT scan data for model training.
"""

import argparse
import logging
from pathlib import Path
import numpy as np
import pandas as pd

from scoring_weights import (
    WEIGHTS,
    SCORE_MIN,
    SCORE_MAX,
    get_risk_tier,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")
logger = logging.getLogger(__name__)


def generate(n_samples: int = 2500, output_path: Path = None) -> pd.DataFrame:
    np.random.seed(42)

    # 1. Technical features
    cvss_score = np.round(np.random.uniform(2.0, 10.0, size=n_samples), 1)
    cvss_exploitability = np.round(np.clip(cvss_score * np.random.uniform(0.2, 0.4, size=n_samples), 0.5, 3.9), 2)
    cvss_impact = np.round(np.clip(cvss_score * np.random.uniform(0.4, 0.65, size=n_samples), 1.0, 6.0), 2)
    vuln_type_encoded = np.random.choice([0, 1, 2, 3, 4, 5], size=n_samples, p=[0.25, 0.20, 0.10, 0.15, 0.15, 0.15])
    exploit_available = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])
    in_threat_feed = np.where(exploit_available == 1, np.random.choice([0, 1], size=n_samples, p=[0.4, 0.6]), 0)
    auth_required = np.random.choice([0, 1], size=n_samples, p=[0.6, 0.4])
    attack_vector_encoded = np.random.choice([0, 1, 2, 3], size=n_samples, p=[0.05, 0.20, 0.25, 0.50])

    # 2. Contextual asset features
    asset_criticality = np.random.choice([1, 2, 3, 4, 5], size=n_samples, p=[0.15, 0.20, 0.30, 0.20, 0.15])
    exposure_encoded = np.random.choice([0, 1, 2, 3], size=n_samples, p=[0.15, 0.40, 0.20, 0.25])
    historical_recurrence = np.random.choice([0, 1, 2, 3, 4, 5], size=n_samples, p=[0.45, 0.25, 0.15, 0.08, 0.05, 0.02])
    days_since_last_scan = np.random.randint(1, 180, size=n_samples)

    # 3. Ground-truth Priority Calculation Formula using shared constants:
    raw_score = (
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

    noise = np.random.normal(0, 1.8, size=n_samples)
    final_score = np.clip(np.round(raw_score * WEIGHTS["scaling_factor"] + noise, 1), SCORE_MIN, SCORE_MAX)

    risk_tiers = [get_risk_tier(s) for s in final_score]

    df = pd.DataFrame({
        "cvss_score": cvss_score,
        "cvss_exploitability": cvss_exploitability,
        "cvss_impact": cvss_impact,
        "asset_criticality": asset_criticality,
        "exposure_encoded": exposure_encoded,
        "vuln_type_encoded": vuln_type_encoded,
        "exploit_available": exploit_available,
        "in_threat_feed": in_threat_feed,
        "auth_required": auth_required,
        "attack_vector_encoded": attack_vector_encoded,
        "historical_recurrence": historical_recurrence,
        "days_since_last_scan": days_since_last_scan,
        "priority_score": final_score,
        "risk_tier": risk_tiers,
    })

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        logger.info("Generated %d synthetic VAPT records -> %s", len(df), output_path)

    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic VAPT training data")
    parser.add_argument("--n", type=int, default=2500, help="Number of samples")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent.parent / "data" / "synthetic_vapt_training.csv",
    )
    args = parser.parse_args()
    generate(args.n, args.out)
