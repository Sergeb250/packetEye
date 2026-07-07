"""Tiered LLM token budgets — brief live calls vs detailed on-demand."""

from __future__ import annotations

TIERS = {
    "brief": {
        "LLM_MAX_TOKENS": 128,
        "LLM_SECONDARY_MAX_TOKENS": 128,
        "OPENROUTER_MAX_TOKENS": 128,
    },
    "medium": {
        "LLM_MAX_TOKENS": 320,
        "LLM_SECONDARY_MAX_TOKENS": 256,
        "OPENROUTER_MAX_TOKENS": 256,
    },
    "detailed": {
        "LLM_MAX_TOKENS": 1024,
        "LLM_SECONDARY_MAX_TOKENS": 768,
        "OPENROUTER_MAX_TOKENS": 512,
    },
    "report": {
        "LLM_MAX_TOKENS": 2048,
        "LLM_SECONDARY_MAX_TOKENS": 1536,
        "OPENROUTER_MAX_TOKENS": 1024,
    },
}


def with_tier(config: dict, tier: str = "medium") -> dict:
    """Return config copy with capped max_tokens for the requested detail tier."""
    caps = TIERS.get(tier, TIERS["medium"])
    out = dict(config)
    for key, cap in caps.items():
        existing = int(out.get(key, cap))
        out[key] = min(existing, cap)
    out["LLM_DETAIL_TIER"] = tier
    return out


def live_triage_config(config: dict, *, models: int = 2, tier: str = "medium") -> dict:
    """Config for live packet triage — shared budget split across models."""
    base = with_tier(config, tier)
    per_model = int(base.get("LLM_LIVE_PACKET_MAX_TOKENS", 256))
    if tier == "brief":
        per_model = min(per_model, 160)
    elif tier == "detailed":
        per_model = min(int(config.get("LLM_LIVE_PACKET_MAX_TOKENS", 512)), 512)
    split = max(64, per_model // max(1, models))
    base["LLM_MAX_TOKENS"] = split
    base["LLM_SECONDARY_MAX_TOKENS"] = split
    base["OPENROUTER_MAX_TOKENS"] = split
    return base
