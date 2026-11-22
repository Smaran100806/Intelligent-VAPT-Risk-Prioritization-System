"""
generate_synthetic_data.py — Generate synthetic VAPT scan data for model training.

Produces a labeled CSV/JSON dataset with:
  - Vulnerability features (CVSS, asset type, severity, exploit availability …)
  - Binary label: `high_priority` (1 = should be fixed immediately, 0 = can wait)

Usage:
    python ml/generate_synthetic_data.py --n 5000 --out data/synthetic_vapt.csv

Full implementation to be added in the ML milestone.
"""

import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature schema (documents what will be generated — not yet implemented)
# ---------------------------------------------------------------------------
#
# FEATURE_SCHEMA = {
#     "cvss_score":            float,   # 0.0 – 10.0
#     "cvss_exploitability":   float,   # 0.0 – 3.9
#     "cvss_impact":           float,   # 0.0 – 6.0
#     "asset_criticality":     int,     # 1 – 5
#     "asset_type_encoded":    int,     # label-encoded AssetType
#     "exploit_public":        bool,    # known public exploit exists
#     "in_threat_feed":        bool,    # flagged by threat intelligence
#     "days_since_discovery":  int,     # staleness
#     "high_priority":         int,     # TARGET LABEL
# }


def generate(n_samples: int, output_path: Path) -> None:
    """Generate n_samples synthetic records and write to output_path. TODO: implement."""
    raise NotImplementedError("generate() — to be implemented in ML milestone")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic VAPT training data")
    parser.add_argument("--n", type=int, default=5000, help="Number of samples")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent.parent / "data" / "synthetic_vapt.csv",
    )
    args = parser.parse_args()

    logger.info("generate_synthetic_data.py — placeholder. Implementation coming in ML milestone.")
