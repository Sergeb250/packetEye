"""Quick LLM provider connectivity checks for the SOC dashboard."""

from __future__ import annotations

import logging
import time

from app.services.llm.provider import parse_json_response
from app.services.llm.stack import build_live_stack

logger = logging.getLogger(__name__)

_TEST_SYSTEM = "You are a connectivity probe. Reply with JSON only."
_TEST_USER = '{"status":"ok","message":"pong"}'


def _probe_one(name: str, provider, timeout_label: str) -> dict:
    started = time.perf_counter()
    try:
        if hasattr(provider, "max_tokens"):
            provider.max_tokens = 64
        raw = provider.complete(_TEST_SYSTEM, _TEST_USER, temperature=0.0)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        parsed = parse_json_response(raw or "")
        ok = bool(parsed) or (raw and raw.strip() not in ("", "{}"))
        return {
            "name": name,
            "ok": ok,
            "latency_ms": elapsed_ms,
            "model": getattr(provider, "model", None),
            "timeout_sec": timeout_label,
            "sample": (raw or "")[:120],
        }
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        logger.warning("LLM probe %s failed: %s", name, exc)
        return {
            "name": name,
            "ok": False,
            "latency_ms": elapsed_ms,
            "model": getattr(provider, "model", None),
            "error": str(exc)[:200],
        }


def probe_llm_connectivity(config: dict) -> dict:
    """Ping Z.ai + NVIDIA + OpenRouter stack sequentially (fast timeout)."""
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled (LLM_ENABLED=false)"}

    has_key = bool(
        (config.get("ZAI_API_KEY") or "").strip()
        or (config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY"))
    )
    if not has_key:
        return {"ok": False, "error": "No ZAI_API_KEY or NVIDIA_API_KEY configured"}

    timeout = float(config.get("LLM_LIVE_TIMEOUT_SECONDS", 18))
    fast_cfg = {**config, "LLM_TIMEOUT_SECONDS": timeout}
    stack = build_live_stack(fast_cfg, max_models=3)

    results: dict[str, dict] = {}
    for name, prov in stack:
        results[name] = _probe_one(name, prov, str(timeout))

    any_ok = any(r.get("ok") for r in results.values())
    return {
        "ok": any_ok,
        "timeout_sec": timeout,
        "primary_model": config.get("ZAI_MODEL") if config.get("ZAI_API_KEY") else config.get("LLM_MODEL"),
        "model_stack": [getattr(p, "model", n) for n, p in stack],
        "results": results,
    }
