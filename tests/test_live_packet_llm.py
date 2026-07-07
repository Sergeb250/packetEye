"""Tests for live LLM packet triage helpers."""

from app.services.live.live_packet_llm import (
    _disposition_from_results,
    _legacy_from_ai_item,
    _merge_verdicts,
    _parse_batch_results,
)


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


def test_disposition_from_benign_results():
    results = [{"suspicious": False, "ai_status": "true_negative", "_model": "primary"}]
    assert _disposition_from_results(results, None, []) == "true_negative"


def test_legacy_from_ai_item_maps_status():
    item = _legacy_from_ai_item({"ai_status": "true_positive", "severity": "high", "confidence": 0.9})
    assert item["suspicious"] is True
    assert item["ai_status"] == "true_positive"
    assert item["disposition_suggested"] == "true_positive"

    benign = _legacy_from_ai_item({"ai_status": "benign", "confidence": 0.95})
    assert benign["suspicious"] is False
    assert benign["ai_status"] == "benign"


def test_parse_batch_results_maps_three_indices():
    parsed = {
        "results": [
            {"index": 0, "ai_status": "true_positive", "severity": "high", "confidence": 0.9},
            {"index": 1, "ai_status": "true_negative", "severity": "info", "confidence": 0.85},
            {"index": 2, "ai_status": "benign", "severity": "info", "confidence": 0.7},
        ]
    }
    out = _parse_batch_results(parsed, 3)
    assert out is not None
    assert len(out) == 3
    assert out[0]["ai_status"] == "true_positive"
    assert out[0]["suspicious"] is True
    assert out[1]["ai_status"] == "true_negative"
    assert out[2]["ai_status"] == "benign"
    assert _disposition_from_results([out[0]], None, []) == "true_positive"
    assert _disposition_from_results([out[1]], None, []) == "true_negative"


def test_parse_batch_results_incomplete_returns_none():
    parsed = {"results": [{"index": 0, "ai_status": "open", "severity": "info", "confidence": 0.5}]}
    assert _parse_batch_results(parsed, 3) is None
