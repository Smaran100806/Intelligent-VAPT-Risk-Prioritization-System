"""
generate_synthetic_data.py — Generate synthetic VAPT scan data for model training.

Generates 2,000+ realistic vulnerability records with technical and contextual features
and computes ground-truth continuous priority_score (0-100) and risk_tier.
"""

import argparse
import logging
from pathlib import Path
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")
logger = logging.getLogger(__name__)

# Feature Encoding schema:
# exposure_encoded: isolated=0, internal=1, dmz=2, internet-facing=3
# vuln_type_encoded: other=0, xss=1, lfi=2, ssrf=3, sqli=4, rce=5
# attack_vector_encoded: physical=0, local=1, adjacent=2, network=3

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

    # 3. Ground-truth Priority Calculation Formula:
    # High impact on business risk combines CVSS + Asset Criticality + Exposure + Threat Intel + Recurrence
    score = (
        (cvss_score * 3.8) +
        (cvss_impact * 2.2) +
        (asset_criticality * 4.5) +
        (exposure_encoded * 5.2) +
        (exploit_available * 10.0) +
        (in_threat_feed * 8.5) +
        (attack_vector_encoded * 2.5) +
        (historical_recurrence * 1.8) -
        (auth_required * 4.0)
    )

    # Normalize to 0-100 range and add slight realistic noise
    noise = np.random.normal(0, 1.8, size=n_samples)
    final_score = np.clip(np.round(score * 0.95 + noise, 1), 5.0, 99.8)

    # Risk tiers matching backend thresholds
    # Critical: >= 75.0, High: >= 50.0, Medium: >= 25.0, Low: < 25.0
    risk_tier = []
    for s in final_score:
        if s >= 75.0:
            risk_tier.append("Critical")
        elif s >= 50.0:
            risk_tier.append("High")
        elif s >= 25.0:
            risk_tier.append("Medium")
        else:
            risk_tier.append("Low")

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
        "risk_tier": risk_tier
    })

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        logger.info(f"Generated {len(df)} synthetic VAPT records -> {output_path}")
        logger.info(f"Risk Tier Breakdown:\n{df['risk_tier'].value_counts().to_string()}")

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
