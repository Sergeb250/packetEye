"""Tests for async runner and OSINT error handling."""

import asyncio

from app.services.enrichment.async_runner import run_async
from app.services.enrichment.orchestrator import EnrichmentOrchestrator
from app.services.enrichment.virustotal import TokenBucket


async def _return_value():
    return 42


def test_run_async_executes_coroutine():
    assert run_async(_return_value()) == 42


def test_run_async_multiple_calls():
    assert run_async(_return_value()) == 42
    assert run_async(_return_value()) == 42


async def _use_token_bucket():
    bucket = TokenBucket(60)
    await bucket.acquire()
    return True


def test_token_bucket_across_loops():
    assert run_async(_use_token_bucket()) is True
    assert run_async(_use_token_bucket()) is True


def test_compute_verdict_skips_vt_error():
    orch = EnrichmentOrchestrator({})
    mal, conf, signals = orch._compute_verdict({
        "virustotal": {"error": "event loop"},
        "abuseipdb": {"abuseConfidenceScore": 0},
    })
    assert mal is False
    vt_sig = next(s for s in signals if s["provider"] == "virustotal")
    assert "lookup failed" in vt_sig["reason"]
