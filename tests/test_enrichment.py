"""Tests for enrichment orchestrator."""

import pytest

from app.services.enrichment.orchestrator import EnrichmentOrchestrator


@pytest.fixture
def orchestrator():
    return EnrichmentOrchestrator({"ENRICHMENT_CACHE_TTL_HOURS": 24})


def test_compute_verdict_clean(orchestrator):
    enrichment = {"virustotal": {"malicious": 0}, "abuseipdb": {"abuseConfidenceScore": 0}}
    is_mal, conf = orchestrator._compute_verdict(enrichment)
    assert is_mal is False


def test_compute_verdict_malicious(orchestrator):
    enrichment = {"virustotal": {"malicious": 5}, "abuseipdb": {"abuseConfidenceScore": 50}}
    is_mal, conf = orchestrator._compute_verdict(enrichment)
    assert is_mal is True
    assert conf > 0
