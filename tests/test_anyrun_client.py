"""Tests for ANY.RUN TI Lookup client."""

from app.services.enrichment.anyrun import AnyRunClient


def test_anyrun_normalize_empty():
    assert AnyRunClient._normalize({}) == {}


def test_anyrun_normalize_malicious():
    raw = {
        "summary": {"threatLevel": 2, "tags": ["remcos"], "lastSeen": "2026-01-01"},
        "sourceTasks": [{"related": "https://app.any.run/abc"}],
        "destinationIP": [{"destinationIP": "1.2.3.4"}],
    }
    out = AnyRunClient._normalize(raw)
    assert out["verdict"] == "Malicious"
    assert out["threat_level"] == 2
    assert out["task_count"] == 1


def test_anyrun_no_key_returns_empty():
    import asyncio

    client = AnyRunClient("")
    assert asyncio.run(client.lookup_ip("1.2.3.4")) == {}
