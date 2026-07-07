"""SOC chatbot — full JSON context for traffic, flows, alerts, and OSINT."""

from __future__ import annotations

import logging
import re

from app.services.llm.context_builder import build_rich_context
from app.services.llm.ensemble import get_llm_ensemble
from app.services.llm.prompts import (
    CHAT_USER_BRIEF_SUFFIX,
    CHAT_USER_DETAILED_SUFFIX,
    SYSTEM_CHAT_BRIEF,
    SYSTEM_CHAT_DETAILED,
)
from app.services.llm.provider import provider_for_model
from app.services.llm.stack import is_allowed_chat_model, parse_chat_models
from app.services.llm.tokens import with_tier

logger = logging.getLogger(__name__)

MAX_MESSAGE_CHARS = 4000

_DETAIL_PATTERNS = re.compile(
    r"(?i)\b(explain more|more detail|full analysis|full report|diagram|mermaid|"
    r"deep dive|expand|elaborate|playbook|step.?by.?step)\b"
)


def resolve_detail_tier(
    detail_tier: str,
    message: str,
    *,
    report_page: bool = False,
) -> str:
    tier = (detail_tier or "auto").strip().lower()
    if tier in ("brief", "detailed"):
        return tier
    if report_page or _DETAIL_PATTERNS.search(message or ""):
        return "detailed"
    return "brief"


def chat(
    config: dict,
    message: str,
    history: list[dict] | None = None,
    analysis_id: str | None = None,
    finding_id: str | None = None,
    flow_id: str | None = None,
    context_payload: dict | None = None,
    model: str | None = None,
    detail_tier: str = "auto",
    report_page: bool = False,
) -> dict:
    message = str(message or "").strip()[:MAX_MESSAGE_CHARS]
    if not message:
        return {"ok": False, "error": "Empty message."}
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM is disabled (LLM_ENABLED=false)."}
    if not (config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")):
        return {"ok": False, "error": "No LLM API key configured. Set NVIDIA_API_KEY in .env."}

    model_id = (model or "").strip() or None
    if model_id and not is_allowed_chat_model(config, model_id):
        allowed = ", ".join(parse_chat_models(config))
        return {"ok": False, "error": f"Unknown model. Allowed: {allowed}"}

    tier = resolve_detail_tier(detail_tier, message, report_page=report_page)
    tier_cfg = with_tier(dict(config), "detailed" if tier == "detailed" else "brief")
    if tier == "brief":
        tier_cfg["LLM_MAX_TOKENS"] = int(config.get("CHATBOT_BRIEF_MAX_TOKENS", 256))
        max_ctx = int(config.get("CHATBOT_BRIEF_MAX_CONTEXT_CHARS", 12000))
    else:
        max_ctx = int(config.get("CHATBOT_MAX_CONTEXT_CHARS", 32000))

    context = build_rich_context(
        analysis_id=analysis_id,
        finding_id=finding_id,
        flow_id=flow_id,
        client_payload=context_payload,
        max_chars=max_ctx,
    )

    max_history = int(config.get("CHATBOT_MAX_HISTORY", 10))
    transcript_lines = []
    for turn in (history or [])[-max_history:]:
        role = "Analyst" if turn.get("role") == "user" else "Assistant"
        transcript_lines.append(f"{role}: {str(turn.get('content', ''))[:1200]}")
    transcript = "\n".join(transcript_lines)

    system = SYSTEM_CHAT_DETAILED if tier == "detailed" else SYSTEM_CHAT_BRIEF
    suffix = CHAT_USER_DETAILED_SUFFIX if tier == "detailed" else CHAT_USER_BRIEF_SUFFIX
    user_prompt = (
        f"=== INVESTIGATION CONTEXT (JSON) ===\n{context}\n\n"
        + (f"=== CONVERSATION SO FAR ===\n{transcript}\n\n" if transcript else "")
        + f"=== ANALYST QUESTION ===\n{message}\n\n"
        + suffix
    )

    try:
        if model_id:
            prov = provider_for_model(
                tier_cfg,
                model_id,
                max_tokens=int(tier_cfg.get("LLM_MAX_TOKENS", 256)),
            )
            raw = prov.complete(system, user_prompt, temperature=0.3 if tier == "detailed" else 0.2)
        else:
            ensemble = get_llm_ensemble(tier_cfg)
            raw = ensemble.complete_text(
                system, user_prompt, temperature=0.3 if tier == "detailed" else 0.2, detail_tier=tier
            )
    except Exception as exc:
        logger.exception("Chatbot completion failed")
        return {"ok": False, "error": f"LLM request failed: {exc}"}

    reply = (raw or "").strip()
    if not reply or reply == "{}":
        return {"ok": False, "error": "The LLM returned no answer — check the API key and model."}
    return {
        "ok": True,
        "reply": reply,
        "format": "markdown",
        "detail_tier": tier,
        "model": model_id or config.get("LLM_MODEL"),
    }
