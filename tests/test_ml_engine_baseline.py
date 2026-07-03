"""Tests for MLEngine baseline loading and scoring."""

import json

import joblib
import numpy as np
import pytest
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

from app.services.detection.features import FEATURE_NAMES, save_feature_schema
from app.services.detection.ml_engine import (
    MLEngine,
    ScoreCalibrator,
    compute_score_calibration,
)


@pytest.fixture
def baseline_artifacts(tmp_path):
    rng = np.random.default_rng(42)
    X = rng.random((200, len(FEATURE_NAMES)))
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(n_estimators=10, contamination=0.05, random_state=42)
    model.fit(X_scaled)

    model_path = tmp_path / "isolation_forest_base.pkl"
    scaler_path = tmp_path / "feature_scaler.pkl"
    schema_path = tmp_path / "feature_schema.json"
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    save_feature_schema(schema_path)
    return model_path, scaler_path, schema_path


def test_ml_engine_loads_baseline(baseline_artifacts):
    model_path, scaler_path, schema_path = baseline_artifacts
    engine = MLEngine(
        model_path=model_path,
        scaler_path=scaler_path,
        schema_path=schema_path,
        train_on_pcap_fallback=False,
    )
    assert engine.has_baseline

    flows = [
        {
            "id": "f1",
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "dst_port": 443,
            "protocol": "TCP",
            "duration_ms": 1000,
            "bytes_sent": 500,
            "bytes_recv": 1500,
            "packets_sent": 5,
            "packets_recv": 10,
        }
    ]
    results = engine.score_flows(flows)
    assert len(results) == 1
    assert "anomaly_score" in results[0]


def test_ml_engine_no_fallback_returns_empty(tmp_path):
    engine = MLEngine(
        model_path=tmp_path / "missing.pkl",
        train_on_pcap_fallback=False,
    )
    results = engine.score_flows([{"id": "x", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
    assert results == []


def test_calibrator_boundary_maps_to_five():
    """decision_function == 0 (sklearn predict flip point) must map to 5.0."""
    assert ScoreCalibrator().normalize(0.0) == pytest.approx(5.0)
    assert ScoreCalibrator(d_min=-0.2, d_max=0.3).normalize(0.0) == pytest.approx(5.0)


def test_calibrator_monotonic_and_bounded():
    cal = ScoreCalibrator(d_min=-0.2, d_max=0.3)
    scores = cal.normalize_array(np.array([0.3, 0.15, 0.0, -0.1, -0.2, -0.5]))
    assert list(scores) == sorted(scores)
    assert scores[0] == pytest.approx(0.0)
    assert scores[-1] == pytest.approx(10.0)
    # -0.1 is halfway to d_min → 7.5
    assert scores[3] == pytest.approx(7.5)


def test_calibrator_falls_back_without_file(tmp_path):
    cal = ScoreCalibrator.load(tmp_path / "missing.json")
    assert not cal.is_calibrated
    assert cal.normalize(0.0) == pytest.approx(5.0)
    assert cal.normalize(-0.2) == pytest.approx(10.0)


def test_compute_and_load_calibration_roundtrip(tmp_path, baseline_artifacts):
    model_path, scaler_path, _ = baseline_artifacts
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    rng = np.random.default_rng(7)
    X = scaler.transform(rng.random((100, len(FEATURE_NAMES))))
    calibration = compute_score_calibration(model, X)
    assert calibration["d_min"] < 0 < calibration["d_max"]

    path = tmp_path / "score_calibration.json"
    path.write_text(json.dumps(calibration), encoding="utf-8")
    cal = ScoreCalibrator.load(path)
    assert cal.is_calibrated
    # Anomalies (negative decision scores) always land above the 5.0 boundary.
    assert cal.normalize(calibration["d_min"]) == pytest.approx(10.0)
    assert cal.normalize(calibration["d_max"]) == pytest.approx(0.0)


def test_ml_engine_scores_with_calibration(baseline_artifacts, tmp_path):
    model_path, scaler_path, schema_path = baseline_artifacts
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    rng = np.random.default_rng(11)
    calibration = compute_score_calibration(
        model, scaler.transform(rng.random((100, len(FEATURE_NAMES))))
    )
    calibration_path = tmp_path / "score_calibration.json"
    calibration_path.write_text(json.dumps(calibration), encoding="utf-8")

    engine = MLEngine(
        model_path=model_path,
        scaler_path=scaler_path,
        schema_path=schema_path,
        calibration_path=calibration_path,
        train_on_pcap_fallback=False,
    )
    assert engine.calibrator.is_calibrated
    results = engine.score_flows(
        [
            {
                "id": "f1",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "dst_port": 443,
                "protocol": "TCP",
                "duration_ms": 1000,
                "bytes_sent": 500,
                "bytes_recv": 1500,
                "packets_sent": 5,
                "packets_recv": 10,
            }
        ]
    )
    assert len(results) == 1
    assert 0.0 <= results[0]["anomaly_score"] <= 10.0
