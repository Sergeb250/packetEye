"""Tests for live LLM packet triage helpers."""

from app.services.live.live_packet_llm import _merge_verdicts


def test_merge_verdicts_requires_confidence_or_dual_agree():
    single_low = [{"suspicious": True, "severity": "high", "confidence": 0.4, "_model": "primary"}]
    assert _merge_verdicts(single_low, 0.55) is None

    single_high = [{"suspicious": True, "severity": "high", "confidence": 0.8, "_model": "primary", "summary": "SSH scan"}]
    merged = _merge_verdicts(single_high, 0.55)
    assert merged is not None
    assert merged["severity"] == "high"

    dual = [
        {"suspicious": True, "severity": "medium", "confidence": 0.5, "_model": "primary", "summary": "a"},
        {"suspicious": True, "severity": "high", "confidence": 0.52, "_model": "secondary", "summary": "b"},
    ]
    merged2 = _merge_verdicts(dual, 0.55)
    assert merged2 is not None
    assert merged2["severity"] == "high"


def test_merge_verdicts_ignores_benign():
    assert _merge_verdicts([{"suspicious": False, "confidence": 0.9}], 0.55) is None
