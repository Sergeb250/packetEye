"""AI-drafted escalation email subject and body."""

from __future__ import annotations

import json
import logging

from app.services.live.alert_service import AlertService
from app.services.live.triage_registry import get_incident
from app.services.llm.prompts import ESCALATION_DRAFT_PROMPT, SYSTEM_ANALYST
from app.services.llm.provider import parse_json_response, provider_for_model
from app.services.llm.tokens import with_tier

logger = logging.getLogger(__name__)


def _load_context(
    context_type: str,
    session_id: str | None,
    alert_id: str | None,
    incident_id: str | None,
) -> dict:
    ctx: dict = {"context_type": context_type}
    if context_type == "alert" and session_id and alert_id:
        for alert in AlertService.get_alerts(session_id, since_ts=0):
            if alert.get("id") == alert_id or alert.get("finding_id") == alert_id:
                ctx["alert"] = alert
                break
    elif context_type == "incident" and session_id and incident_id:
        row = get_incident(session_id, incident_id)
        if row:
            ctx["incident"] = row
    return ctx


def draft_escalation_email(
    config: dict,
    *,
    context_type: str = "alert",
    session_id: str | None = None,
    alert_id: str | None = None,
    incident_id: str | None = None,
    detail_tier: str = "brief",
) -> dict:
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled"}

    payload = _load_context(context_type, session_id, alert_id, incident_id)
    if not payload.get("alert") and not payload.get("incident"):
        return {"ok": False, "error": "No alert or incident context found"}

    tier = "detailed" if detail_tier == "detailed" else "brief"
    tier_cfg = with_tier(dict(config), tier)
    max_tokens = 256 if tier == "brief" else 512
    model = tier_cfg.get("LLM_MODEL", "minimaxai/minimax-m3")
    user = ESCALATION_DRAFT_PROMPT.format(context=json.dumps(payload, default=str)[:6000])
    prov = provider_for_model(tier_cfg, model, max_tokens=max_tokens)
    try:
        raw = prov.complete(SYSTEM_ANALYST, user, temperature=0.2)
        parsed = parse_json_response(raw or "")
        subject = (parsed or {}).get("subject") or "packetEye — alert escalation"
        body = (parsed or {}).get("body") or raw or ""
        if not body.strip():
            return {"ok": False, "error": "Empty draft from LLM"}
        return {"ok": True, "subject": subject.strip(), "body": body.strip()}
    except Exception as exc:
        logger.warning("Escalation draft failed: %s", exc)
        return {"ok": False, "error": str(exc)}
