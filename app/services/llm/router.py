"""Task-aware LLM router — route jobs to Z.ai / NVIDIA / OpenRouter by availability."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.services.llm.provider import parse_json_response
from app.services.llm.rate_limit import note_failure, provider_call_slot, wait_if_backoff
from app.services.llm.stack import build_live_stack

logger = logging.getLogger(__name__)

# Task → preferred model stack keys (first available wins for single-shot; all tried for parallel).
TASK_PREFERENCES: dict[str, list[str]] = {
    "live_triage": ["zai", "nvidia", "nvidia_secondary", "openrouter"],
    "live_verify": ["nvidia", "nvidia_secondary", "zai", "openrouter"],
    "alert_enrich": ["zai", "nvidia", "openrouter"],
    "osint_summary": ["zai", "nvidia", "openrouter"],
    "suricata_rule": ["zai", "nvidia", "openrouter"],
    "deep_inspect": ["nvidia", "zai", "openrouter"],
    "chat": ["zai", "nvidia", "openrouter"],
    "big_task": ["nvidia", "nvidia_secondary", "zai", "openrouter"],
}

_pool_lock = threading.Lock()
_pools: dict[int, "ModelRouter"] = {}


class ModelRouter:
    """Dispatch LLM work across up to 3 providers; skip busy or backed-off models."""

    def __init__(self, config: dict, *, max_models: int = 3):
        stack = build_live_stack(config, max_models=max_models)
        self.stack: dict[str, object] = {name: prov for name, prov in stack}
        self.config = config

    def model_names(self) -> list[str]:
        return list(self.stack.keys())

    def _call_model(self, name: str, system: str, user: str, temperature: float) -> tuple[str, dict | None, str | None]:
        prov = self.stack.get(name)
        if not prov:
            return name, None, "not configured"
        label = getattr(prov, "label", name)
        wait_if_backoff(label)
        try:
            with provider_call_slot(label):
                raw = prov._complete_inner(system, user, temperature)
                if raw and raw.strip() not in ("", "{}"):
                    raw = raw.strip()
                else:
                    return name, None, "empty or unparseable response"
                parsed = parse_json_response(raw)
                if parsed:
                    parsed["_model"] = name
                    return name, parsed, None
                return name, None, "empty or unparseable response"
        except Exception as exc:
            note_failure(label, exc)
            logger.debug("ModelRouter %s failed: %s", name, exc)
            return name, None, str(exc)

    def complete_json(
        self,
        task_type: str,
        system: str,
        user: str,
        *,
        temperature: float = 0.2,
        parallel: bool = False,
    ) -> tuple[dict | None, dict[str, dict], list[str]]:
        """Single best result + all model outputs + errors."""
        prefs = TASK_PREFERENCES.get(task_type, list(self.stack.keys()))
        ordered = [n for n in prefs if n in self.stack]
        ordered.extend(n for n in self.stack if n not in ordered)

        model_outputs: dict[str, dict] = {}
        errors: list[str] = []

        if parallel and len(ordered) > 1:
            with ThreadPoolExecutor(max_workers=min(3, len(ordered))) as pool:
                futures = {
                    pool.submit(self._call_model, name, system, user, temperature): name
                    for name in ordered
                }
                for fut in as_completed(futures):
                    name, parsed, err = fut.result()
                    if parsed:
                        model_outputs[name] = parsed
                    if err:
                        errors.append(f"{name}: {err}")
        else:
            for name in ordered:
                _, parsed, err = self._call_model(name, system, user, temperature)
                if parsed:
                    model_outputs[name] = parsed
                    break
                if err:
                    errors.append(f"{name}: {err}")

        best = None
        for name in ordered:
            if name in model_outputs:
                best = model_outputs[name]
                break
        return best, model_outputs, errors

    def parallel_triage(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.1,
    ) -> tuple[dict[str, dict], list[str]]:
        """Run all configured models in parallel (each uses its own provider slot)."""
        _, outputs, errors = self.complete_json(
            "live_triage",
            system,
            user,
            temperature=temperature,
            parallel=True,
        )
        return outputs, errors


def get_model_router(config: dict) -> ModelRouter:
    """Process-wide cached router keyed by config id (Flask app config dict)."""
    key = id(config)
    with _pool_lock:
        router = _pools.get(key)
        if router is None:
            router = ModelRouter(config)
            _pools[key] = router
        return router
