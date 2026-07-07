"""Brief on-demand explanation for AI triage verdicts."""

from __future__ import annotations

import json
import logging

from app.services.live.triage_registry import get_incident
from app.services.llm.prompts import TRIAGE_EXPLAIN_SYSTEM, TRIAGE_EXPLAIN_USER
from app.services.llm.provider import parse_json_response, provider_for_model
from app.services.llm.tokens import with_tier

logger = logging.getLogger(__name__)


def explain_incident(config: dict, session_id: str, incident_id: str) -> dict:
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled"}
    if not (config.get("NVIDIA_API_KEY") or config.get("LLM_API_KEY")):
        return {"ok": False, "error": "No LLM API key configured"}

    row = get_incident(session_id, incident_id)
    if not row:
        return {"ok": False, "error": "Incident not found"}

    brief_cfg = with_tier(dict(config), "brief")
    user = TRIAGE_EXPLAIN_USER.format(
        incident=json.dumps(row, default=str)[:5000],
        disposition=row.get("disposition") or "open",
        summary=row.get("llm_merged_summary") or "",
    )
    model = brief_cfg.get("LLM_MODEL", "minimaxai/minimax-m3")
    prov = provider_for_model(brief_cfg, model, max_tokens=int(brief_cfg.get("LLM_MAX_TOKENS", 128)))
    try:
        raw = prov.complete(TRIAGE_EXPLAIN_SYSTEM, user, temperature=0.1)
        parsed = parse_json_response(raw or "")
        text = (parsed or {}).get("explanation") or (raw or "").strip()
        if not text or text in ("", "{}"):
            return {"ok": False, "error": "Empty LLM response"}
        return {"ok": True, "explanation": text, "format": "text"}
    except Exception as exc:
        logger.warning("Triage explain failed: %s", exc)
        return {"ok": False, "error": str(exc)}
