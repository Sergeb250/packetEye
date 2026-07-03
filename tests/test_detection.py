"""Tests for detection engine."""

from pathlib import Path

import pytest

from app.services.detection.engine import DetectionEngine, WhitelistEngine


@pytest.fixture
def engine():
    base = Path(__file__).resolve().parent.parent
    config = {
        "DETECTION_RULES_DIR": base / "detection_rules",
        "WHITELIST_PATH": base / "whitelist" / "default_whitelist.yaml",
        "ML_MODEL_PATH": base / "ml_models" / "isolation_forest_base.pkl",
        "ML_SCALER_PATH": base / "ml_models" / "feature_scaler.pkl",
        "ML_FEATURE_SCHEMA_PATH": base / "ml_models" / "feature_schema.json",
        "ML_ANOMALY_THRESHOLD": 7.5,
        "ML_TRAIN_ON_PCAP_FALLBACK": False,
        "MAX_FLOWS_ML_SCORING": 1000,
        "WHITELIST_ENABLED": True,
    }
    return DetectionEngine(config)


class FakeFlow:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "flow-1")
        for k, v in kwargs.items():
            setattr(self, k, v)

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


def test_whitelist_cdn(engine):
    wl = engine.whitelist
    assert wl.is_whitelisted_flow({"dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP"})


def test_portscan_horizontal(engine):
    flows = []
    for port in range(1, 60):
        flows.append(
            FakeFlow(
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                dst_port=port,
                start_time=__import__("datetime").datetime(2026, 1, 1, 12, 0, 0),
                protocol="TCP",
            )
        )
    results = engine._portscan_horizontal(flows, {"min_ports": 50, "window_seconds": 30}, [], [])
    assert len(results) >= 1


def test_dns_entropy(engine):
    flows = [
        FakeFlow(
            id="f1",
            dns_queries=["aGVsbG8gd29ybGQ.example.com"],
            application_layer="DNS",
        )
    ]
    results = engine._dns_entropy(flows, {"min_entropy": 2.0}, [], [])
    assert isinstance(results, list)
