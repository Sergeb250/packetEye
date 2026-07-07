"""Quick LLM provider connectivity checks for the SOC dashboard."""

from __future__ import annotations

import logging
import time

from app.services.llm.provider import parse_json_response
from app.services.llm.rate_limit import (
    is_provider_blocked,
    llm_call_slot,
    note_failure,
    wait_if_backoff,
)
from app.services.llm.stack import build_live_stack

logger = logging.getLogger(__name__)

_TEST_SYSTEM = "You are a connectivity probe. Reply with JSON only."
_TEST_USER = '{"status":"ok","message":"pong"}'


def _probe_one(name: str, provider, timeout_label: str) -> dict:
    label = getattr(provider, "label", name)
    model = getattr(provider, "model", None)
    if is_provider_blocked(label):
        return {
            "name": name,
            "ok": False,
            "skipped": True,
            "model": model,
            "timeout_sec": timeout_label,
            "error": "rate limited — wait and retry",
        }

    started = time.perf_counter()
    saved_tokens = getattr(provider, "max_tokens", None)
    try:
        wait_if_backoff(label)
        with llm_call_slot(label):
            if saved_tokens is not None:
                provider.max_tokens = 64
            raw = provider._complete_inner(_TEST_SYSTEM, _TEST_USER, temperature=0.0)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        parsed = parse_json_response(raw or "")
        ok = bool(parsed) or (raw and raw.strip() not in ("", "{}"))
        err = None
        if not ok:
            if raw and raw.strip() == "{}":
                err = (
                    "empty response ({}) — Z.ai may be out of credits; "
                    "recharge at https://z.ai or try ZAI_MODEL=glm-4.7-flash"
                )
            else:
                err = "empty or unparseable response"
        return {
            "name": name,
            "ok": ok,
            "latency_ms": elapsed_ms,
            "model": model,
            "timeout_sec": timeout_label,
            "sample": (raw or "")[:120],
            **({} if ok else {"error": err}),
        }
    except Exception as exc:
        note_failure(label, exc)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        logger.warning("LLM probe %s failed: %s", name, exc)
        msg = str(exc)[:200]
        if "1113" in msg or "Insufficient balance" in msg:
            msg = "Z.ai insufficient balance — recharge your account at https://z.ai"
        elif "1211" in msg or "Unknown Model" in msg:
            msg = f"Unknown Z.ai model ({model}) — set ZAI_MODEL=glm-4.7-flash in .env"
        elif "429" in msg or "Too Many Requests" in msg:
            msg = f"NVIDIA rate limited ({model}) — wait and retry or reduce LLM_LIVE_PACKETS_PER_MIN"
        return {
            "name": name,
            "ok": False,
            "latency_ms": elapsed_ms,
            "model": model,
            "error": msg,
        }
    finally:
        if saved_tokens is not None:
            provider.max_tokens = saved_tokens


def probe_llm_connectivity(config: dict) -> dict:
    """Ping configured LLM stack (single provider or multi-model fallbacks)."""
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled (LLM_ENABLED=false)"}

    from app.services.llm.stack import _single_provider_mode

    single = _single_provider_mode(config)
    has_key = bool(
        (config.get("ZAI_API_KEY") or "").strip()
        or (config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY"))
    )
    if not has_key:
        return {"ok": False, "error": "No ZAI_API_KEY or NVIDIA_API_KEY configured"}

    timeout = float(config.get("LLM_PROBE_TIMEOUT_SECONDS", 12))
    fast_cfg = {**config, "LLM_TIMEOUT_SECONDS": timeout, "LLM_LIVE_TIMEOUT_SECONDS": timeout}
    max_models = 1 if single else 3
    stack = build_live_stack(fast_cfg, max_models=max_models)

    results: dict[str, dict] = {}
    for name, prov in stack:
        results[name] = _probe_one(name, prov, str(timeout))

    any_ok = any(r.get("ok") for r in results.values())
    primary = config.get("LLM_MODEL")
    if single == "zai":
        primary = config.get("ZAI_MODEL")
    elif not single and (config.get("ZAI_API_KEY") or "").strip():
        primary = config.get("ZAI_MODEL")
    return {
        "ok": any_ok,
        "single_provider": single or None,
        "sequential": True,
        "timeout_sec": timeout,
        "primary_model": primary,
        "model_stack": [getattr(p, "model", n) for n, p in stack],
        "results": results,
    }
