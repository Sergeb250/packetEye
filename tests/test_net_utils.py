"""Tests for shared IP classification and ML alert suppression."""

from pathlib import Path

import yaml

from app.services.detection.engine import WhitelistEngine
from app.services.net_utils import (
    is_external_ip,
    is_internal_ip,
    is_local_only_flow,
    ml_alert_suppressed,
    suricata_alert_suppressed,
)


def test_multicast_and_private_are_internal():
    assert is_internal_ip("192.168.1.1") is True
    assert is_internal_ip("239.255.255.250") is True
    assert is_internal_ip("224.0.0.251") is True
    assert is_internal_ip("127.0.0.1") is True
    assert is_external_ip("8.8.8.8") is True
    assert is_external_ip("239.255.255.250") is False


def test_local_only_flow():
    flow = {"src_ip": "192.168.1.10", "dst_ip": "239.255.255.250", "dst_port": 1900, "protocol": "UDP"}
    assert is_local_only_flow(flow) is True


def test_ml_alert_suppressed_for_ssdp_multicast():
    flow = {
        "src_ip": "192.168.1.10",
        "dst_ip": "239.255.255.250",
        "dst_port": 1900,
        "protocol": "UDP",
    }
    suppressed, reason = ml_alert_suppressed(flow)
    assert suppressed is True
    assert "local-only" in reason or "multicast" in reason or "private" in reason


def test_ml_alert_not_suppressed_for_public_dst():
    flow = {
        "src_ip": "192.168.1.10",
        "dst_ip": "1.1.1.1",
        "dst_port": 443,
        "protocol": "TCP",
    }
    suppressed, _ = ml_alert_suppressed(flow)
    assert suppressed is False


def test_whitelist_ssdp_port(tmp_path):
    wl = tmp_path / "wl.yaml"
    wl.write_text(
        yaml.dump(
            {
                "cidr_ranges": ["239.255.255.250/32"],
                "domains": [],
                "ports_protocols": [{"port": 1900, "protocol": "UDP", "note": "SSDP"}],
            }
        ),
        encoding="utf-8",
    )
    engine = WhitelistEngine(Path(wl))
    flow = {
        "src_ip": "10.0.0.5",
        "dst_ip": "239.255.255.250",
        "dst_port": 1900,
        "protocol": "UDP",
    }
    suppressed, reason = ml_alert_suppressed(flow, engine)
    assert suppressed is True


def test_suricata_not_suppressed_for_test_net():
    flow = {"src_ip": "203.0.113.1", "dst_ip": "192.168.1.1", "dst_port": 22, "protocol": "TCP"}
    suppressed, _ = suricata_alert_suppressed(flow)
    assert suppressed is False


def test_ml_lab_mode_allows_internal_dst():
    flow = {"src_ip": "203.0.113.1", "dst_ip": "192.168.1.1", "dst_port": 22, "protocol": "TCP"}
    suppressed, _ = ml_alert_suppressed(flow, strict_c2_filter=False)
    assert suppressed is False
