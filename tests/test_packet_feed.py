"""Tests for live packet feed row mapping."""

from app.services.live.packet_feed import eve_event_to_row, scapy_packet_to_row


def test_eve_alert_row_critical():
    row = eve_event_to_row(
        {
            "event_type": "alert",
            "timestamp": "2026-07-03T12:00:00Z",
            "src_ip": "10.0.0.5",
            "dest_ip": "192.168.1.10",
            "src_port": 4444,
            "dest_port": 22,
            "proto": "TCP",
            "alert": {"signature": "SSH brute force", "severity": 1},
        }
    )
    assert row is not None
    assert row["severity"] == "critical"
    assert "SSH" in row["info"]


def test_eve_flow_row_external_medium():
    row = eve_event_to_row(
        {
            "event_type": "flow",
            "timestamp": "2026-07-03T12:00:01Z",
            "src_ip": "192.168.1.5",
            "dest_ip": "8.8.8.8",
            "src_port": 54321,
            "dest_port": 443,
            "proto": "TCP",
            "flow": {"bytes_toserver": 100, "bytes_toclient": 200, "pkts_toserver": 2, "pkts_toclient": 3},
        }
    )
    assert row is not None
    assert row["severity"] in ("medium", "high", "info")


def test_scapy_tcp_row():
    try:
        from scapy.all import IP, TCP, Ether
    except ImportError:
        return

    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80, flags="S")
    row = scapy_packet_to_row(pkt)
    assert row is not None
    assert row["protocol"] == "TCP"
    assert row["dst_port"] == 80
