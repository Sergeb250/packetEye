"""Tests for enrichment orchestrator."""

import pytest

from app.services.enrichment.orchestrator import EnrichmentOrchestrator


@pytest.fixture
def orchestrator():
    return EnrichmentOrchestrator({"ENRICHMENT_CACHE_TTL_HOURS": 24})


def test_compute_verdict_clean(orchestrator):
    enrichment = {"virustotal": {"malicious": 0}, "abuseipdb": {"abuseConfidenceScore": 0}}
    is_mal, conf, signals = orchestrator._compute_verdict(enrichment)
    assert is_mal is False
    assert isinstance(signals, list)


def test_compute_verdict_malicious(orchestrator):
    enrichment = {"virustotal": {"malicious": 5}, "abuseipdb": {"abuseConfidenceScore": 50}}
    is_mal, conf, signals = orchestrator._compute_verdict(enrichment)
    assert is_mal is True
    assert conf > 0
    assert any(s.get("triggered") for s in signals)


def test_verdict_breakdown_otx(orchestrator):
    enrichment = {"virustotal": {"malicious": 0}, "otx": {"pulse_count": 50}}
    is_mal, _, signals = orchestrator._compute_verdict(enrichment)
    assert is_mal is True
    otx_sig = next(s for s in signals if s["provider"] == "otx")
    assert otx_sig["triggered"] is True
