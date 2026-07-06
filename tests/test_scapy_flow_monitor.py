"""Tests for Scapy flow aggregation."""

import time

from app.services.live.scapy_flow_monitor import ScapyFlowMonitor


def test_scapy_flow_monitor_aggregates_packets():
    mon = ScapyFlowMonitor(idle_seconds=0.1)
    now = time.time()
    pkt = {
        "id": 1,
        "source": "scapy",
        "event_type": "packet",
        "timestamp": now,
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "src_port": 40000,
        "dst_port": 443,
        "protocol": "TCP",
        "length": 100,
    }
    mon._ingest_packet(pkt, now)
    mon._ingest_packet({**pkt, "id": 2, "timestamp": now + 0.01, "length": 50}, now + 0.01)
    flows = mon._flush_idle(now + 1.0)
    assert len(flows) == 1
    assert flows[0]["bytes_sent"] == 150
    assert flows[0]["packets_sent"] == 2
    assert flows[0]["dst_port"] == 443


def test_scapy_flow_monitor_empty_poll():
    mon = ScapyFlowMonitor(idle_seconds=5)
    events = mon.poll_events()
    assert events["flows"] == []
    assert events["alerts"] == []
