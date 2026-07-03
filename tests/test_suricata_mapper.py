"""Tests for Suricata EVE flow mapping."""

import json
from pathlib import Path

from app.services.live.suricata_mapper import eve_alert_to_alert_dict, eve_flow_to_flow_dict


def test_eve_flow_to_flow_dict():
    fixture = Path(__file__).parent / "fixtures" / "suricata_eve_flow.json"
    event = json.loads(fixture.read_text(encoding="utf-8"))
    flow = eve_flow_to_flow_dict(event, flow_id="test-flow-1")
    assert flow is not None
    assert flow["src_ip"] == "10.0.0.5"
    assert flow["dst_ip"] == "8.8.8.8"
    assert flow["dst_port"] == 443
    assert flow["protocol"] == "TCP"
    assert flow["bytes_sent"] == 2400
    assert flow["bytes_recv"] == 8000
    assert flow["duration_ms"] == 5000
    assert flow["is_external_dst"] is True


def test_non_flow_event_returns_none():
    assert eve_flow_to_flow_dict({"event_type": "alert"}) is None


def test_eve_alert_to_alert_dict():
    event = {
        "event_type": "alert",
        "timestamp": "2026-07-02T12:00:00.000000+0000",
        "src_ip": "192.168.1.20",
        "src_port": 51515,
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "proto": "TCP",
        "app_proto": "ssh",
        "alert": {
            "signature": "SSH brute force attempt",
            "signature_id": 1000001,
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
            "action": "allowed",
        },
    }
    alert = eve_alert_to_alert_dict(event)
    assert alert is not None
    assert alert["signature"] == "SSH brute force attempt"
    assert alert["signature_id"] == 1000001
    assert alert["severity"] == "high"  # suricata severity 1 == most severe
    assert alert["src_ip"] == "192.168.1.20"
    assert alert["dst_ip"] == "10.0.0.5"
    assert alert["dst_port"] == 22
    assert alert["protocol"] == "TCP"


def test_eve_alert_requires_signature():
    assert eve_alert_to_alert_dict({"event_type": "alert", "alert": {}}) is None
    assert eve_alert_to_alert_dict({"event_type": "flow"}) is None
