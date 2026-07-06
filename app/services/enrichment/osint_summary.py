"""LLM summary of OSINT enrichment for SOC overview."""

from __future__ import annotations

import json
import logging

from app.services.llm.ensemble import get_llm_ensemble
from app.services.llm.prompts import SYSTEM_ANALYST
from app.services.llm.tokens import with_tier

logger = logging.getLogger(__name__)

OSINT_SUMMARY_BRIEF = """Summarize OSINT for a SOC analyst in 1-2 short sentences.

Target: {target} ({target_type})
OSINT JSON: {osint}
Alert context: {alert}

Rules: CDN/Fastly → likely benign. Ignore provider errors in verdict.
Respond ONLY JSON: {{"summary": "max 2 sentences", "verdict": "clean|suspicious|malicious|unknown", "highlights": ["one line each, max 3"]}}"""

OSINT_SUMMARY_DETAILED = """Detailed OSINT briefing for a SOC analyst.

Target: {target} ({target_type})
OSINT JSON: {osint}
Alert context: {alert}

Include: verdict rationale, key provider signals, FP assessment, recommended next step.
Respond ONLY JSON: {{"summary": "4-6 sentences", "verdict": "clean|suspicious|malicious|unknown", "highlights": ["..."], "recommended_action": "..."}}"""


def _compact_osint(enrichment: dict) -> str:
    slim = {}
    for provider, data in (enrichment or {}).items():
        if not data:
            continue
        if isinstance(data, dict) and data.get("error"):
            slim[provider] = {"error": str(data["error"])[:80]}
        elif provider == "geo":
            slim[provider] = {k: data.get(k) for k in ("country", "city", "isp", "org", "asn") if data.get(k)}
        elif provider == "abuseipdb":
            slim[provider] = {k: data.get(k) for k in ("abuseConfidenceScore", "usageType", "countryCode") if k in data}
        elif provider == "virustotal":
            slim[provider] = {k: data.get(k) for k in ("malicious", "suspicious", "harmless") if k in data and not data.get("error")}
        elif provider == "internetdb":
            slim[provider] = {k: data.get(k) for k in ("tags", "hostnames", "ports") if data.get(k)}
        else:
            slim[provider] = data
    return json.dumps(slim, default=str)[:6000]


def summarize_osint(
    config: dict,
    *,
    target: str,
    target_type: str,
    enrichment: dict,
    alert_context: dict | None = None,
    detail_level: str = "medium",
) -> dict:
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled"}
    if not (config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")):
        return {"ok": False, "error": "No LLM API key configured"}

    tier = "detailed" if detail_level == "detailed" else "medium" if detail_level == "medium" else "brief"
    fast_cfg = with_tier(
        {
            **config,
            "LLM_TIMEOUT_SECONDS": float(config.get("LLM_LIVE_TIMEOUT_SECONDS", 22)),
        },
        tier,
    )
    template = OSINT_SUMMARY_DETAILED if tier == "detailed" else OSINT_SUMMARY_BRIEF
    user = template.format(
        target=target,
        target_type=target_type,
        osint=_compact_osint(enrichment),
        alert=json.dumps(alert_context or {}, default=str)[:2000],
    )
    try:
        ensemble = get_llm_ensemble(fast_cfg)
        parsed = ensemble.complete_json(
            SYSTEM_ANALYST,
            user,
            temperature=0.2,
            cache_prefix=f"osint_summary:{target}:{tier}",
        )
        if not parsed or not parsed.get("summary"):
            return {"ok": False, "error": "LLM returned empty summary (rate limit or credits — try again)"}
        return {"ok": True, "detail_level": tier, **parsed}
    except Exception as exc:
        logger.warning("OSINT summary failed for %s: %s", target, exc)
        return {"ok": False, "error": str(exc)[:200]}
