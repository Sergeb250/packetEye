"""Quick LLM provider connectivity checks for the SOC dashboard."""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.services.llm.ensemble import _build_secondary
from app.services.llm.provider import get_provider, parse_json_response

logger = logging.getLogger(__name__)

_TEST_SYSTEM = "You are a connectivity probe. Reply with JSON only."
_TEST_USER = '{"status":"ok","message":"pong"}'


def _probe_one(name: str, provider, timeout_label: str) -> dict:
    started = time.perf_counter()
    try:
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
            "error": str(exc),
        }


def probe_llm_connectivity(config: dict) -> dict:
    """Ping primary + secondary models in parallel (fast timeout)."""
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled (LLM_ENABLED=false)"}

    api_key = config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")
    if not api_key:
        return {"ok": False, "error": "No NVIDIA_API_KEY / LLM_API_KEY configured"}

    timeout = float(config.get("LLM_LIVE_TIMEOUT_SECONDS", 18))
    fast_cfg = {
        **config,
        "LLM_TIMEOUT_SECONDS": timeout,
        "LLM_MAX_TOKENS": 64,
        "LLM_SECONDARY_MAX_TOKENS": 64,
    }
    primary = get_provider(fast_cfg)
    secondary = _build_secondary(fast_cfg)

    probes: list[tuple[str, object]] = [("primary", primary)]
    if secondary:
        probes.append(("secondary", secondary))

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=len(probes)) as pool:
        futures = {
            pool.submit(_probe_one, name, prov, str(timeout)): name
            for name, prov in probes
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as exc:
                results[name] = {"name": name, "ok": False, "error": str(exc)}

    all_ok = all(r.get("ok") for r in results.values())
    return {
        "ok": all_ok,
        "timeout_sec": timeout,
        "primary_model": config.get("LLM_MODEL"),
        "secondary_model": config.get("LLM_SECONDARY_MODEL") or None,
        "results": results,
    }
