#!/usr/bin/env python3
"""Sweep calibrated ML anomaly thresholds against CIC-IDS2017 BENIGN vs attack flows."""

import json
import logging
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.services.detection.features import build_feature_matrix_from_cic, load_feature_schema
from app.services.detection.ml_engine import ScoreCalibrator
from scripts.cic_loader import load_cic_flows
from scripts.cic_preprocess import clean_cic_dataframe, filter_benign, is_attack_label

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ML_DIR = ROOT / "ml_models"
DEFAULT_SAMPLE_SIZE = 20000
MAX_BENIGN_FP_RATE = 0.10


def run_threshold_tuning(
    model=None,
    scaler=None,
    feature_names=None,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    random_state: int = 42,
    output_path: Path | None = None,
) -> dict:
    """Sweep calibrated 0-10 thresholds; recommend the best-F1 point.

    The recommendation maximizes F1 on a labeled sample subject to the benign
    false-positive rate staying under MAX_BENIGN_FP_RATE; if no threshold
    satisfies the cap, the unconstrained best-F1 threshold is used.
    """
    model = model or joblib.load(ML_DIR / "isolation_forest_base.pkl")
    scaler = scaler or joblib.load(ML_DIR / "feature_scaler.pkl")
    feature_names = feature_names or load_feature_schema(ML_DIR / "feature_schema.json")
    calibrator = ScoreCalibrator.load(ML_DIR / "score_calibration.json")
    if not calibrator.is_calibrated:
        logger.warning(
            "No score_calibration.json found — using fallback scale. "
            "Retrain with scripts/train_baseline.py for calibrated scores."
        )

    all_flows = clean_cic_dataframe(load_cic_flows(day=None))
    benign = filter_benign(all_flows)

    def scores_for(df):
        X = build_feature_matrix_from_cic(df)[feature_names].values.astype(float)
        raw = model.decision_function(scaler.transform(X))
        return calibrator.normalize_array(raw)

    benign_n = min(sample_size, len(benign))
    labeled_n = min(sample_size, len(all_flows))
    benign_scores = scores_for(benign.sample(n=benign_n, random_state=random_state))
    labeled_sample = all_flows.sample(n=labeled_n, random_state=random_state)
    y_true = np.array([1 if is_attack_label(l) else 0 for l in labeled_sample["Label"]])
    labeled_scores = scores_for(labeled_sample)

    best = None
    best_capped = None
    sweep = []
    for threshold in np.arange(3.0, 9.01, 0.25):
        y_pred = (labeled_scores >= threshold).astype(int)
        tp = int(((y_pred == 1) & (y_true == 1)).sum())
        fp = int(((y_pred == 1) & (y_true == 0)).sum())
        fn = int(((y_pred == 0) & (y_true == 1)).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        benign_fp = float((benign_scores >= threshold).mean())

        entry = {
            "threshold": float(threshold),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "benign_fp_rate": round(benign_fp, 4),
            "attack_recall": round(recall, 4),
        }
        sweep.append(entry)

        if best is None or f1 > best["f1"]:
            best = entry
        if benign_fp <= MAX_BENIGN_FP_RATE and (best_capped is None or f1 > best_capped["f1"]):
            best_capped = entry

    recommended = best_capped or best
    recommended = dict(recommended)
    recommended["selection"] = (
        f"max F1 with benign FP <= {MAX_BENIGN_FP_RATE:.0%}"
        if best_capped
        else "max F1 (no threshold met the benign FP cap)"
    )

    out = {"recommended": recommended, "sweep": sweep, "calibrated": calibrator.is_calibrated}
    path = output_path or (ML_DIR / "recommended_threshold.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    logger.info("Recommended threshold: %s", recommended)
    logger.info("Set ML_ANOMALY_THRESHOLD=%.2f in .env to apply it.", recommended["threshold"])
    return out


def main():
    run_threshold_tuning()


if __name__ == "__main__":
    main()
