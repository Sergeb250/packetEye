"""Tests for LLM token tiers and rate limiting."""

from app.services.llm.rate_limit import split_budget
from app.services.llm.tokens import live_triage_config, with_tier


def test_split_budget_two_models():
    assert split_budget(256, 2) == 128
    assert split_budget(320, 2) == 160


def test_with_tier_caps_tokens():
    cfg = with_tier({"LLM_MAX_TOKENS": 4096, "OPENROUTER_MAX_TOKENS": 2048}, "medium")
    assert cfg["LLM_MAX_TOKENS"] == 320
    assert cfg["OPENROUTER_MAX_TOKENS"] == 256


def test_live_triage_splits_per_model():
    cfg = live_triage_config({"LLM_LIVE_PACKET_MAX_TOKENS": 256}, models=2, tier="medium")
    assert cfg["LLM_MAX_TOKENS"] == 128
    assert cfg["LLM_SECONDARY_MAX_TOKENS"] == 128
