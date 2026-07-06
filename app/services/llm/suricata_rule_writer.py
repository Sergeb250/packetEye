"""AI-assisted Suricata custom rule generation (NVIDIA primary + secondary)."""

from __future__ import annotations

import logging
import re

from app.services.llm.ensemble import get_llm_ensemble

logger = logging.getLogger(__name__)

_SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.I)

RULE_GEN_SYSTEM = """You are a Suricata IDS rule author for packetEye sensors.
Write valid Suricata rules only — no markdown, no prose outside JSON.
Use $HOME_NET for internal/production targets. Use 203.0.113.0/24 (TEST-NET) only when the user asks for lab/soak testing.
Each rule needs a unique sid in the 1000000+ range. Prefer threshold for scans/brute-force patterns."""

RULE_GEN_USER = """Analyst request:
{description}

Existing custom.rules (do NOT reuse these sids — pick new unique sid values):
{existing}

Write one or more Suricata alert rules. Examples:
- SSH brute force: threshold track by_src on port 22
- Port scan: many SYNs to different ports
- HTTP DoS: many requests to port 80

Respond ONLY with JSON:
{{"rules": "alert tcp any any -> $HOME_NET 22 (...);\\n", "explanation": "brief rationale", "sids": [1000120]}}"""


def _used_sids(content: str) -> set[int]:
    return {int(m.group(1)) for m in _SID_RE.finditer(content or "")}


def _next_sid_hint(content: str) -> int:
    used = _used_sids(content)
    if used:
        return max(used) + 1
    return 1000200


def generate_suricata_rules(config: dict, description: str, existing_content: str = "") -> dict:
    description = (description or "").strip()
    if not description:
        return {"ok": False, "error": "Describe what you want to detect."}
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled (LLM_ENABLED=false)."}
    if not (config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")):
        return {"ok": False, "error": "No NVIDIA_API_KEY configured."}

    existing = (existing_content or "").strip()
    hint_sid = _next_sid_hint(existing)
    user = RULE_GEN_USER.format(
        description=description[:2000],
        existing=(existing[:6000] if existing else f"(empty — start sid at {hint_sid})"),
    )

    fast_cfg = {
        **config,
        "LLM_TIMEOUT_SECONDS": float(config.get("LLM_LIVE_TIMEOUT_SECONDS", 22)),
        "LLM_MAX_TOKENS": int(config.get("LLM_LIVE_PACKET_MAX_TOKENS", 512)),
    }
    ensemble = get_llm_ensemble(fast_cfg)
    parsed = ensemble.complete_json(
        RULE_GEN_SYSTEM,
        user,
        temperature=0.15,
        cache_prefix="suricata_rule:gen",
    )
    if not parsed:
        return {"ok": False, "error": "LLM returned no rule — test NVIDIA models and retry."}

    rules_text = str(parsed.get("rules") or "").strip()
    if not rules_text or "alert" not in rules_text.lower():
        return {"ok": False, "error": "LLM response did not contain valid Suricata rule text."}

    # Normalize: ensure each rule line ends properly
    lines = []
    for line in rules_text.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            lines.append(line)
            continue
        if not line.endswith(";"):
            line += ";"
        lines.append(line)

    new_sids = _used_sids("\n".join(lines))
    conflict = new_sids & _used_sids(existing)
    if conflict:
        return {
            "ok": False,
            "error": f"Generated sid(s) already in use: {sorted(conflict)}. Edit sids and retry.",
            "rules": "\n".join(lines),
        }

    return {
        "ok": True,
        "rules": "\n".join(lines),
        "explanation": parsed.get("explanation") or "",
        "sids": sorted(new_sids),
        "primary_model": config.get("LLM_MODEL"),
        "secondary_model": config.get("LLM_SECONDARY_MODEL") or None,
    }
