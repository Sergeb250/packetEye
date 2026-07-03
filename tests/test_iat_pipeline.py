"""Integration test: IAT values persist from parser output through Flow model to ML features."""

import pytest

from app.models.analysis import Flow
from app.services.detection.features import build_feature_matrix


def _synthetic_flow_data():
    return {
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "src_port": 40000,
        "dst_port": 443,
        "protocol": "TCP",
        "duration_ms": 150,
        "bytes_sent": 400,
        "bytes_recv": 1200,
        "packets_sent": 4,
        "packets_recv": 4,
        "iat_mean": 0.05,
        "iat_std": 0.01,
        "iat_max": 0.12,
        "fwd_iat_mean": 0.04,
        "is_external_dst": True,
    }


def test_synthetic_flow_has_nonzero_iat_features():
    matrix = build_feature_matrix([{"id": "f1", **_synthetic_flow_data()}])
    assert matrix.iloc[0]["iat_mean"] == pytest.approx(0.05)
    assert matrix.iloc[0]["iat_std"] == pytest.approx(0.01)
    assert matrix.iloc[0]["iat_max"] == pytest.approx(0.12)


def test_flow_model_persists_iat_for_ml(flask_app):
    flow_data = _synthetic_flow_data()

    with flask_app.app_context():
        from app.extensions import db

        flow = Flow(
            analysis_id="test-analysis",
            src_ip=flow_data["src_ip"],
            dst_ip=flow_data["dst_ip"],
            src_port=flow_data["src_port"],
            dst_port=flow_data["dst_port"],
            protocol=flow_data["protocol"],
            duration_ms=flow_data["duration_ms"],
            bytes_sent=flow_data["bytes_sent"],
            bytes_recv=flow_data["bytes_recv"],
            packets_sent=flow_data["packets_sent"],
            packets_recv=flow_data["packets_recv"],
            iat_mean=flow_data["iat_mean"],
            iat_std=flow_data["iat_std"],
            iat_max=flow_data["iat_max"],
            fwd_iat_mean=flow_data["fwd_iat_mean"],
        )
        db.session.add(flow)
        db.session.commit()

        d = flow.to_dict()
        assert d["iat_mean"] > 0
        assert d["iat_std"] > 0

        matrix = build_feature_matrix([{"id": flow.id, **d, "start_time": None}])
        assert matrix.iloc[0]["iat_mean"] > 0
        assert matrix.iloc[0]["duration_ms_log"] == pytest.approx(__import__("math").log1p(150))
