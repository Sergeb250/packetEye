"""Tests for SSH/port-scan heuristics."""

from app.services.live.triage_heuristics import TriageHeuristics


def test_ssh_brute_burst():
    h = TriageHeuristics(window_sec=60)
    hit = None
    for i in range(8):
        hit = h.analyze({
            "timestamp": 1000 + i,
            "src_ip": "203.0.113.50",
            "dst_ip": "192.168.1.10",
            "dst_port": 22,
            "protocol": "TCP",
        })
    assert hit is not None
    assert hit["attack_type"] == "SSH-Patator"
    assert "ssh_syn_burst" in hit["indicators"][0]


def test_port_scan_entropy():
    h = TriageHeuristics(window_sec=60)
    hit = None
    for i in range(16):
        hit = h.analyze({
            "timestamp": 2000 + i * 0.1,
            "src_ip": "10.0.0.99",
            "dst_ip": "192.168.1.1",
            "dst_port": 1000 + i,
            "protocol": "TCP",
        })
    assert hit is not None
    assert hit["attack_type"] == "PortScan"


def test_benign_single_ssh_no_hit():
    h = TriageHeuristics()
    hit = h.analyze({
        "timestamp": 3000,
        "src_ip": "10.0.0.1",
        "dst_ip": "192.168.1.5",
        "dst_port": 22,
        "protocol": "TCP",
    })
    assert hit is None
