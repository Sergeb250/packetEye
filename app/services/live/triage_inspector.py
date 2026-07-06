"""On-demand deep LLM inspection for triage incidents."""

from __future__ import annotations

import json
import logging

from app.services.llm.ensemble import get_llm_ensemble
from app.services.llm.tokens import with_tier

logger = logging.getLogger(__name__)

DEEP_SYSTEM = """You are packetEye's senior SOC analyst. Provide a detailed briefing only when asked.
Use Markdown: Verdict, Evidence, Attack classification, FP risk, Actions. Ground in JSON only."""

DEEP_USER = """Incident row:
{incident}

Related packet/flow:
{packet}

Primary model triage:
{primary}

Secondary model triage:
{secondary}

Provide a thorough analyst briefing."""


def deep_inspect_incident(config: dict, incident: dict) -> dict:
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled"}
    if not (config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")):
        return {"ok": False, "error": "No LLM API key configured"}

    fast_cfg = with_tier(
        {
            **config,
            "LLM_TIMEOUT_SECONDS": float(config.get("LLM_LIVE_TIMEOUT_SECONDS", 22)),
        },
        "detailed",
    )
    user = DEEP_USER.format(
        incident=json.dumps(incident, default=str)[:6000],
        packet=json.dumps(incident.get("packet") or {}, default=str)[:3000],
        primary=json.dumps(incident.get("llm_primary") or {}, default=str)[:2000],
        secondary=json.dumps(incident.get("llm_secondary") or {}, default=str)[:2000],
    )
    try:
        ensemble = get_llm_ensemble(fast_cfg)
        text = ensemble.complete_text(DEEP_SYSTEM, user, temperature=0.2, detail_tier="detailed")
        if not text or text.strip() in ("", "{}"):
            return {"ok": False, "error": "LLM returned empty response"}
        return {
            "ok": True,
            "format": "markdown",
            "analysis": text.strip(),
            "models": [config.get("LLM_MODEL"), config.get("LLM_SECONDARY_MODEL")],
        }
    except Exception as exc:
        logger.warning("Deep inspect failed: %s", exc)
        return {"ok": False, "error": str(exc)}
