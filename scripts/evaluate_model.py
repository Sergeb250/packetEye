#!/usr/bin/env python3
"""Evaluate baseline model on CIC-IDS2017 labeled data."""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.services.detection.features import (
    build_cic_matrix,
    feature_set_of,
    load_feature_schema_info,
)
from app.services.detection.ml_engine import ScoreCalibrator
from scripts.cic_loader import load_cic_flows
from scripts.cic_preprocess import clean_cic_dataframe, is_attack_label

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

ML_DIR = ROOT / "ml_models"
MAX_EVAL_ROWS = 100_000
DEFAULT_THRESHOLD = 5.0


def resolve_threshold() -> float:
    """Prefer the tuned threshold so the benchmark matches app behavior."""
    rec_path = ML_DIR / "recommended_threshold.json"
    if rec_path.exists():
        try:
            data = json.loads(rec_path.read_text(encoding="utf-8"))
            value = (data.get("recommended") or {}).get("threshold")
            if value is not None:
                return float(value)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return DEFAULT_THRESHOLD


def evaluate_split(
    model, scaler, feature_names, df, split_name,
    calibrator=None, threshold=DEFAULT_THRESHOLD, feature_set="legacy",
):
    X_df = build_cic_matrix(df, feature_set)
    mask = X_df[feature_names].notna().all(axis=1).to_numpy()
    df = df.iloc[mask].reset_index(drop=True)
    X = X_df.loc[mask, feature_names].values.astype(float)
    X_scaled = scaler.transform(X)

    label_col = "Label" if "Label" in df.columns else "attack_label"
    y_true = np.array([1 if is_attack_label(l) else 0 for l in df[label_col]])

    # Score exactly like MLEngine.score_flows: calibrated 0-10 vs threshold.
    calibrator = calibrator or ScoreCalibrator()
    norm_scores = calibrator.normalize_array(model.decision_function(X_scaled))
    y_pred = (norm_scores >= threshold).astype(int)

    return {
        "split": split_name,
        "threshold": float(threshold),
        "samples": len(y_true),
        "attacks": int(y_true.sum()),
        "benign": int((y_true == 0).sum()),
        "predicted_anomalies": int(y_pred.sum()),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "classification_report": classification_report(y_true, y_pred, zero_division=0),
    }


def run_benchmark(
    model=None,
    scaler=None,
    feature_names=None,
    max_eval_rows: int = MAX_EVAL_ROWS,
    random_state: int = 42,
    output_path: Path | None = None,
    feature_set: str = "auto",
) -> dict:
    """Evaluate model on stratified all-days labeled sample.

    feature_set "auto" follows the saved feature_schema.json (or the passed
    feature_names) so evaluation always matches the trained model.
    """
    model_path = ML_DIR / "isolation_forest_base.pkl"
    scaler_path = ML_DIR / "feature_scaler.pkl"
    schema_path = ML_DIR / "feature_schema.json"

    if model is None:
        if not model_path.exists():
            raise FileNotFoundError("Model not found. Run training first.")
        model = joblib.load(model_path)
    if scaler is None:
        scaler = joblib.load(scaler_path)
    if feature_names is None:
        info = load_feature_schema_info(schema_path)
        feature_names = info["feature_names"]
        if feature_set == "auto":
            feature_set = info["feature_set"]
    elif feature_set == "auto":
        feature_set = feature_set_of(feature_names)

    calibrator = ScoreCalibrator.load(ML_DIR / "score_calibration.json")
    threshold = resolve_threshold()
    logger.info(
        "Evaluating at calibrated threshold %.2f (calibrated=%s, feature_set=%s, %d features)",
        threshold,
        calibrator.is_calibrated,
        feature_set,
        len(feature_names),
    )

    logger.info("Loading CIC-IDS2017 for evaluation...")
    df = load_cic_flows(day=None, feature_set=feature_set)
    note = "Evaluation uses a stratified sample of all labeled flows (all days)."
    if len(df) > max_eval_rows:
        label_col = "Label" if "Label" in df.columns else "attack_label"
        attack_mask = df[label_col].astype(str).str.upper() != "BENIGN"
        attacks = df[attack_mask]
        benign = df[~attack_mask]
        attack_n = min(len(attacks), max_eval_rows // 5)
        benign_n = max_eval_rows - attack_n
        if attack_n < len(attacks):
            attacks = attacks.sample(n=attack_n, random_state=random_state)
        if benign_n < len(benign):
            benign = benign.sample(n=benign_n, random_state=random_state)
        df = pd.concat([benign, attacks], ignore_index=True)
        logger.info("Eval subsample: %d rows (%d attacks, %d benign)", len(df), len(attacks), len(benign))

    df = clean_cic_dataframe(df, feature_set=feature_set)

    results = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "note": note,
        "threshold": threshold,
        "feature_set": feature_set,
        "score_calibrated": calibrator.is_calibrated,
        "overall": evaluate_split(
            model, scaler, feature_names, df, "all_labeled",
            calibrator=calibrator, threshold=threshold, feature_set=feature_set,
        ),
    }

    label_col = "Label" if "Label" in df.columns else "attack_label"
    by_label = {}
    for label, group in df.groupby(label_col):
        if len(group) < 50:
            continue
        name = str(label)
        by_label[name] = evaluate_split(
            model, scaler, feature_names, group, name,
            calibrator=calibrator, threshold=threshold, feature_set=feature_set,
        )
    results["by_attack_label"] = by_label

    attack_rows = df[df[label_col].astype(str).str.upper() != "BENIGN"]
    if len(attack_rows) >= 50:
        attack_result = evaluate_split(
            model, scaler, feature_names, attack_rows, "all_attacks",
            calibrator=calibrator, threshold=threshold, feature_set=feature_set,
        )
        results["attack_only"] = attack_result
        results["summary"] = {
            "accuracy": attack_result["accuracy"],
            "precision": attack_result["precision"],
            "recall": attack_result["recall"],
            "f1": attack_result["f1"],
        }
        logger.info(
            "Attack detection: accuracy=%.3f recall=%.3f f1=%.3f",
            attack_result["accuracy"],
            attack_result["recall"],
            attack_result["f1"],
        )

    logger.info(
        "Overall: accuracy=%.3f recall=%.3f f1=%.3f",
        results["overall"]["accuracy"],
        results["overall"]["recall"],
        results["overall"]["f1"],
    )

    rec_path = ML_DIR / "recommended_threshold.json"
    if rec_path.exists():
        try:
            results["recommended_threshold"] = json.loads(rec_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    out_path = output_path or (ML_DIR / "benchmark_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    logger.info("Benchmark saved to %s", out_path)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--feature-set",
        choices=["auto", "legacy", "full"],
        default="auto",
        help="auto follows the saved feature_schema.json",
    )
    args = parser.parse_args()
    try:
        run_benchmark(feature_set=args.feature_set)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
