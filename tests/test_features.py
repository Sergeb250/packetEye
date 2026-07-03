"""Tests for shared ML feature extraction."""

import math
from datetime import datetime, timezone

import pandas as pd
import pytest

from app.services.detection.features import (
    FEATURE_NAMES,
    build_feature_matrix,
    build_feature_matrix_from_cic,
    cic_duration_us_to_ms,
    cic_iat_us_to_seconds,
)


def test_feature_names_count():
    assert len(FEATURE_NAMES) == 20


def test_packeteye_flow_feature_shape():
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
            "iat_mean": 0.05,
            "iat_std": 0.01,
            "iat_max": 0.2,
            "fwd_iat_mean": 0.04,
            "start_time": datetime(2026, 1, 1, 14, 0, tzinfo=timezone.utc),
            "is_external_dst": True,
        }
    ]
    matrix = build_feature_matrix(flows)
    assert list(matrix.columns) == ["flow_id"] + FEATURE_NAMES
    assert matrix.iloc[0]["dst_port"] == 443
    assert matrix.iloc[0]["iat_mean"] == 0.05
    assert matrix.iloc[0]["is_external_dst"] == 1
    assert matrix.iloc[0]["time_of_day_hour"] == 14
    assert matrix.iloc[0]["fwd_pkt_len_mean"] == pytest.approx(100.0)  # 500 / 5
    assert matrix.iloc[0]["bwd_pkt_len_mean"] == pytest.approx(150.0)  # 1500 / 10
    assert matrix.iloc[0]["pkt_size_avg"] == pytest.approx(2000 / 15)
    assert matrix.iloc[0]["down_up_ratio"] == pytest.approx(2.0)  # 10 / 5


def test_precomputed_port_entropy_is_used():
    """Live consumers pass rolling entropy; the batch must not overwrite it."""
    flows = [
        {
            "id": "f-live",
            "src_ip": "10.0.0.9",
            "dst_ip": "10.0.0.10",
            "dst_port": 22,
            "protocol": "TCP",
            "duration_ms": 10,
            "bytes_sent": 60,
            "bytes_recv": 0,
            "packets_sent": 1,
            "packets_recv": 0,
            "dst_port_entropy": 7.5,
        }
    ]
    matrix = build_feature_matrix(flows)
    assert matrix.iloc[0]["dst_port_entropy"] == pytest.approx(7.5)


def test_iat_not_zeroed_in_flow_dict():
    flows = [
        {
            "id": "f2",
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.3",
            "dst_port": 80,
            "protocol": "TCP",
            "duration_ms": 500,
            "bytes_sent": 100,
            "bytes_recv": 200,
            "packets_sent": 2,
            "packets_recv": 3,
            "iat_mean": 0.12,
            "iat_std": 0.03,
            "iat_max": 0.25,
            "fwd_iat_mean": 0.11,
        }
    ]
    matrix = build_feature_matrix(flows)
    assert matrix.iloc[0]["iat_mean"] == pytest.approx(0.12)
    assert matrix.iloc[0]["iat_std"] == pytest.approx(0.03)


def test_cic_feature_shape():
    cic_df = pd.DataFrame(
        {
            "Destination Port": [443, 80],
            "Flow Duration": [1000000, 500000],
            "Total Fwd Packets": [10, 5],
            "Total Backward Packets": [8, 4],
            "Total Length of Fwd Packets": [1000, 500],
            "Total Length of Bwd Packets": [800, 400],
            "Flow Bytes/s": [1800.0, 900.0],
            "Flow Packets/s": [18.0, 9.0],
            "Flow IAT Mean": [0.1, 0.2],
            "Flow IAT Std": [0.01, 0.02],
            "Flow IAT Max": [0.5, 0.3],
            "Fwd IAT Mean": [0.09, 0.18],
            "Source IP": ["10.0.0.1", "10.0.0.1"],
            "Destination IP": ["8.8.8.8", "1.1.1.1"],
        }
    )
    matrix = build_feature_matrix_from_cic(cic_df)
    assert len(matrix) == 2
    for col in FEATURE_NAMES:
        assert col in matrix.columns
    assert matrix.iloc[0]["dst_port"] == 443
    assert matrix.iloc[0]["is_external_dst"] == 1
    assert math.isclose(matrix.iloc[0]["duration_ms_log"], math.log1p(cic_duration_us_to_ms(1_000_000)))
    assert matrix.iloc[0]["protocol_encoded"] == 1


def test_cic_duration_and_iat_unit_conversion():
    assert cic_duration_us_to_ms(1_000_000) == 1000.0
    assert cic_iat_us_to_seconds(500_000) == 0.5


def test_cic_protocol_udp():
    cic_df = pd.DataFrame(
        {
            "Destination Port": [53],
            "Flow Duration": [1000],
            "Total Fwd Packets": [1],
            "Total Backward Packets": [1],
            "Total Length of Fwd Packets": [100],
            "Total Length of Bwd Packets": [100],
            "Protocol": [17],
        }
    )
    matrix = build_feature_matrix_from_cic(cic_df)
    assert matrix.iloc[0]["protocol_encoded"] == 2


def test_empty_flows():
    matrix = build_feature_matrix([])
    assert matrix.empty
