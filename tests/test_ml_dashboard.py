"""Tests for ML dashboard data aggregation."""

import json
from pathlib import Path

from app.services.ml_dashboard import (
    _verification_from_tracker,
    build_ml_performance,
)


def test_verification_from_tracker():
    run = {
        "phases": [
            {"name": "training", "metrics": {"train_rows": 1000}},
            {
                "name": "verification",
                "status": "completed",
                "metrics": {"recall": 0.36, "f1": 0.51, "accuracy": 0.86},
            },
        ]
    }
    v = _verification_from_tracker(run)
    assert v["recall"] == 0.36
    assert v["status"] == "completed"


def test_build_ml_performance_from_tracker(tmp_path):
    ml_dir = tmp_path / "ml_models"
    ml_dir.mkdir()
    tracker = ml_dir / "training_tracker"
    tracker.mkdir()

    (ml_dir / "isolation_forest_base.pkl").write_bytes(b"x")
    (ml_dir / "feature_scaler.pkl").write_bytes(b"x")
    (ml_dir / "training_metadata.json").write_text(
        json.dumps({"train_rows": 2000000, "train_day": "all_days_BENIGN"}),
        encoding="utf-8",
    )
    (tracker / "latest_run.json").write_text(
        json.dumps(
            {
                "run_id": "test-run",
                "phases": [
                    {
                        "name": "verification",
                        "metrics": {
                            "accuracy": 0.85,
                            "recall": 0.37,
                            "precision": 0.81,
                            "f1": 0.51,
                            "attacks": 400000,
                            "benign": 1600000,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    config = {
        "ML_MODEL_PATH": ml_dir / "isolation_forest_base.pkl",
        "ML_SCALER_PATH": ml_dir / "feature_scaler.pkl",
        "ML_FEATURE_SCHEMA_PATH": ml_dir / "feature_schema.json",
        "ML_ANOMALY_THRESHOLD": 7.5,
    }
    perf = build_ml_performance(config)
    assert perf["model_loaded"] is True
    assert perf["verification"]["recall"] == 0.37
    assert perf["training"]["train_rows"] == 2000000
