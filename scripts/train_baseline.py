#!/usr/bin/env python3
"""Train Isolation Forest baseline on CIC-IDS2017 BENIGN traffic (all days)."""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.services.detection.features import FEATURE_NAMES, build_feature_matrix_from_cic, save_feature_schema
from app.services.detection.ml_engine import compute_score_calibration, save_score_calibration
from scripts.cic_loader import load_cic_flows
from scripts.cic_preprocess import clean_cic_dataframe, filter_benign

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

ML_DIR = ROOT / "ml_models"

# Isolation Forest degrades when each tree sees too many rows — trees become
# redundant and subtle anomalies (port scans, brute force) stop isolating.
# Small per-tree samples with more trees is the well-established setup.
DEFAULT_N_ESTIMATORS = 300
DEFAULT_MAX_SAMPLES = 4096
DEFAULT_CONTAMINATION = 0.05


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-estimators", type=int, default=DEFAULT_N_ESTIMATORS)
    parser.add_argument(
        "--max-samples",
        type=int,
        default=DEFAULT_MAX_SAMPLES,
        help="Rows per tree (256-8192 recommended; huge values hurt recall)",
    )
    parser.add_argument("--contamination", type=float, default=DEFAULT_CONTAMINATION)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main():
    args = parse_args()
    ML_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("Loading CIC-IDS2017 flows (all days)...")
    flows = filter_benign(clean_cic_dataframe(load_cic_flows(day=None)))

    if len(flows) < 100:
        logger.error("Insufficient BENIGN rows: %d", len(flows))
        sys.exit(1)

    logger.info("Using all %d BENIGN rows (no subsampling)", len(flows))

    train_df = clean_cic_dataframe(flows)
    if len(train_df) < 100:
        logger.error("Insufficient rows after cleaning: %d", len(train_df))
        sys.exit(1)

    X_df = build_feature_matrix_from_cic(train_df)
    X = X_df[FEATURE_NAMES].values.astype(float)

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    max_samples = min(args.max_samples, len(X_scaled))
    model = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        max_samples=max_samples,
        random_state=args.random_state,
        n_jobs=-1,
    )
    logger.info(
        "Training Isolation Forest on %d BENIGN flows (%d trees x %d samples, contamination=%.3f)...",
        len(X_scaled), args.n_estimators, max_samples, args.contamination,
    )
    model.fit(X_scaled)

    logger.info("Calibrating anomaly score scale against benign training scores...")
    calibration = compute_score_calibration(model, X_scaled, random_state=args.random_state)

    joblib.dump(model, ML_DIR / "isolation_forest_base.pkl")
    joblib.dump(scaler, ML_DIR / "feature_scaler.pkl")
    save_feature_schema(ML_DIR / "feature_schema.json")
    save_score_calibration(calibration, ML_DIR / "score_calibration.json")

    meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "CIC-IDS2017",
        "train_day": "all_days_BENIGN",
        "train_date": "mixed",
        "train_label": "BENIGN",
        "train_rows": len(X_scaled),
        "feature_count": len(FEATURE_NAMES),
        "n_estimators": args.n_estimators,
        "contamination": args.contamination,
        "max_samples": max_samples,
        "score_calibration": {"d_min": calibration["d_min"], "d_max": calibration["d_max"]},
        "unit_notes": {
            "cic_flow_duration": "microseconds -> duration_ms_log uses milliseconds",
            "cic_iat": "microseconds -> seconds",
            "packeteye_duration": "milliseconds",
            "packeteye_iat": "seconds",
        },
    }
    with open(ML_DIR / "training_metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    logger.info("Saved model artifacts to %s", ML_DIR)
    logger.info("Next: python scripts/tune_threshold.py, then python scripts/evaluate_model.py")


if __name__ == "__main__":
    main()
