"""On-demand deep LLM inspection for triage incidents."""

from __future__ import annotations

import json
import logging

from app.services.llm.prompts import DEEP_INSPECT_SYSTEM, DEEP_INSPECT_USER
from app.services.llm.router import get_model_router
from app.services.llm.tokens import with_tier

logger = logging.getLogger(__name__)


def deep_inspect_incident(config: dict, incident: dict) -> dict:
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled"}
    if not (config.get("ZAI_API_KEY") or config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")):
        return {"ok": False, "error": "No LLM API key configured"}

    fast_cfg = with_tier(
        {
            **config,
            "LLM_TIMEOUT_SECONDS": float(config.get("LLM_LIVE_TIMEOUT_SECONDS", 22)),
        },
        "detailed",
    )
    user = DEEP_INSPECT_USER.format(
        incident=json.dumps(incident, default=str)[:6000],
        packet=json.dumps(incident.get("packet") or {}, default=str)[:3000],
        primary=json.dumps(incident.get("llm_primary") or {}, default=str)[:2000],
        secondary=json.dumps(incident.get("llm_secondary") or {}, default=str)[:2000],
    )
    try:
        router = get_model_router(fast_cfg)
        best, outputs, errors = router.complete_json(
            "deep_inspect",
            DEEP_INSPECT_SYSTEM,
            user,
            temperature=0.2,
            parallel=False,
        )
        text = (best or {}).get("analysis") or (best or {}).get("summary") or ""
        if not text and outputs:
            first = next(iter(outputs.values()), {})
            text = first.get("analysis") or first.get("summary") or json.dumps(first)
        if not text or str(text).strip() in ("", "{}"):
            err = "; ".join(errors[:2]) if errors else "empty response"
            return {"ok": False, "error": err}
        return {
            "ok": True,
            "format": "markdown",
            "analysis": str(text).strip(),
            "models": router.model_names(),
        }
    except Exception as exc:
        logger.warning("Deep inspect failed: %s", exc)
        return {"ok": False, "error": str(exc)}
