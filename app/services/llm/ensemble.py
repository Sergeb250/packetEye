"""Multi-model LLM orchestration — parallel analysis, synthesis, and fallback."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.services.llm.provider import (
    LLMProvider,
    NVIDIAProvider,
    OpenRouterProvider,
    get_provider,
    parse_json_response,
)

logger = logging.getLogger(__name__)

BIG_TASK_PREFIXES = ("exec:", "hunt:", "finding:")
LIVE_PREFIXES = ("osint_summary:", "live_alert", "live_packet", "suricata_rule:")

SYNTHESIS_SYSTEM = """You are the lead SOC analyst on packetEye. Multiple AI models analyzed the same alert.
Merge their outputs into ONE authoritative answer. Prefer conservative severity when models disagree.
Ground the result in evidence from the drafts — do not invent IOCs or events. Output ONLY valid JSON."""

SYNTHESIS_USER = """Original analyst task:
{task}

Model drafts (JSON or text):
{drafts}

Return a single merged JSON object using the same schema as the drafts. If drafts disagree on severity, use the higher severity only when at least two drafts agree or evidence supports it."""

TEXT_SYNTHESIS_SYSTEM = """You are the lead SOC analyst on packetEye. Merge multiple analyst drafts into one clear Markdown response for a SOC operator. Resolve disagreements conservatively and cite only evidence present in the drafts."""

TEXT_SYNTHESIS_USER = """Analyst question:
{task}

Draft responses:
{drafts}

Produce one unified Markdown answer."""


def _is_big_task(cache_prefix: str) -> bool:
    return any(cache_prefix.startswith(p) for p in BIG_TASK_PREFIXES)


def _is_live_task(cache_prefix: str) -> bool:
    return any(cache_prefix.startswith(p) for p in LIVE_PREFIXES)


def _build_secondary(config: dict) -> LLMProvider | None:
    secondary_model = (config.get("LLM_SECONDARY_MODEL") or "").strip()
    api_key = config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY", "")
    if not secondary_model or not api_key:
        return None
    timeout = float(config.get("LLM_TIMEOUT_SECONDS", 45))
    max_tokens = int(config.get("LLM_SECONDARY_MAX_TOKENS", config.get("LLM_MAX_TOKENS", 512)))
    base_url = config.get("NVIDIA_API_BASE", NVIDIAProvider.DEFAULT_BASE_URL)
    return NVIDIAProvider(api_key, secondary_model, base_url, max_tokens, timeout)


def _build_fallback(config: dict) -> LLMProvider | None:
    key = (config.get("OPENROUTER_API_KEY") or "").strip()
    if not key:
        return None
    model = config.get("OPENROUTER_MODEL", "deepseek/deepseek-chat")
    base_url = config.get("OPENROUTER_BASE", OpenRouterProvider.DEFAULT_BASE_URL)
    timeout = float(config.get("LLM_TIMEOUT_SECONDS", 45))
    max_tokens = int(config.get("OPENROUTER_MAX_TOKENS", 256))
    return OpenRouterProvider(key, model, base_url, max_tokens, timeout=timeout)


class LLMEnsemble:
    """Primary + secondary (GLM) parallel runs with synthesis; OpenRouter fallback."""

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("LLM_ENSEMBLE_ENABLED", True)
        self.parallel = config.get("LLM_ENSEMBLE_PARALLEL", True)
        self.primary = get_provider(config)
        self.secondary = _build_secondary(config)
        self.fallback = _build_fallback(config)

    def _call_one(self, provider: LLMProvider, system: str, user: str, temperature: float) -> str:
        try:
            raw = provider.complete(system, user, temperature)
            if raw and raw.strip() not in ("", "{}"):
                return raw.strip()
        except Exception as exc:
            logger.warning("LLM provider call failed: %s", exc)
        return ""

    def _sequential_raw(self, system: str, user: str, temperature: float) -> list[tuple[str, str]]:
        """Primary then secondary — respects shared rate limit (avoids 429)."""
        results: list[tuple[str, str]] = []
        for name, prov in [("primary", self.primary), ("secondary", self.secondary)]:
            if not prov:
                continue
            text = self._call_one(prov, system, user, temperature)
            if text:
                results.append((name, text))
        return results

    def _parallel_raw(self, system: str, user: str, temperature: float) -> list[tuple[str, str]]:
        providers: list[tuple[str, LLMProvider]] = [("primary", self.primary)]
        if self.secondary:
            providers.append(("secondary", self.secondary))
        results: list[tuple[str, str]] = []
        with ThreadPoolExecutor(max_workers=len(providers)) as pool:
            futures = {
                pool.submit(self._call_one, prov, system, user, temperature): name
                for name, prov in providers
            }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    text = fut.result()
                    if text:
                        results.append((name, text))
                except Exception as exc:
                    logger.warning("Parallel LLM %s failed: %s", name, exc)
        return results

    def _synthesize_json(self, task: str, drafts: list[tuple[str, str]]) -> dict:
        if len(drafts) == 1:
            return parse_json_response(drafts[0][1])
        draft_text = "\n\n".join(f"--- {name} ---\n{body}" for name, body in drafts)
        synth_user = SYNTHESIS_USER.format(task=task[:4000], drafts=draft_text[:12000])
        merged = self._call_one(self.primary, SYNTHESIS_SYSTEM, synth_user, 0.1)
        parsed = parse_json_response(merged)
        if parsed:
            return parsed
        for _, body in drafts:
            parsed = parse_json_response(body)
            if parsed:
                return parsed
        return {}

    def _synthesize_text(self, task: str, drafts: list[tuple[str, str]]) -> str:
        if len(drafts) == 1:
            return drafts[0][1]
        draft_text = "\n\n".join(f"--- {name} ---\n{body}" for name, body in drafts)
        synth_user = TEXT_SYNTHESIS_USER.format(task=task[:4000], drafts=draft_text[:12000])
        merged = self._call_one(self.primary, TEXT_SYNTHESIS_SYSTEM, synth_user, 0.2)
        if merged:
            return merged
        return drafts[0][1]

    def _fallback_chain_json(self, system: str, user: str, temperature: float) -> dict:
        order: list[tuple[str, LLMProvider | None]] = [
            ("primary", self.primary),
            ("secondary", self.secondary),
            ("fallback", self.fallback),
        ]
        for name, prov in order:
            if not prov:
                continue
            raw = self._call_one(prov, system, user, temperature)
            parsed = parse_json_response(raw)
            if parsed:
                logger.info("LLM ensemble used %s (JSON)", name)
                return parsed
        return {}

    def complete_json(
        self,
        system: str,
        user: str,
        temperature: float = 0.2,
        cache_prefix: str = "",
    ) -> dict:
        use_parallel = (
            self.enabled
            and self.parallel
            and self.secondary
            and _is_big_task(cache_prefix)
            and not _is_live_task(cache_prefix)
        )
        if use_parallel:
            drafts = self._parallel_raw(system, user, temperature)
            if len(drafts) >= 2:
                parsed = self._synthesize_json(user, drafts)
                if parsed:
                    logger.info("LLM ensemble parallel+synthesis for %s", cache_prefix)
                    return parsed
            if drafts:
                parsed = parse_json_response(drafts[0][1])
                if parsed:
                    return parsed
        elif self.enabled and self.secondary and not _is_live_task(cache_prefix):
            drafts = self._sequential_raw(system, user, temperature)
            if len(drafts) >= 2:
                parsed = self._synthesize_json(user, drafts)
                if parsed:
                    return parsed
            if drafts:
                parsed = parse_json_response(drafts[0][1])
                if parsed:
                    return parsed
        return self._fallback_chain_json(system, user, temperature)

    def complete_text(self, system: str, user: str, temperature: float = 0.3, *, detail_tier: str = "medium") -> str:
        big = len(user) > int(self.config.get("LLM_ENSEMBLE_BIG_CONTEXT_CHARS", 8000))
        detailed = detail_tier == "detailed"
        use_parallel = (
            self.enabled
            and self.parallel
            and self.secondary
            and big
            and detailed
        )
        if use_parallel:
            drafts = self._parallel_raw(system, user, temperature)
            if len(drafts) >= 2:
                return self._synthesize_text(user, drafts)
            if drafts:
                return drafts[0][1]
        if self.enabled and self.secondary:
            drafts = self._sequential_raw(system, user, temperature)
            if len(drafts) >= 2 and detailed:
                return self._synthesize_text(user, drafts)
            if drafts:
                return drafts[0][1]
        for name, prov in [("primary", self.primary), ("secondary", self.secondary), ("fallback", self.fallback)]:
            if not prov:
                continue
            raw = self._call_one(prov, system, user, temperature)
            if raw:
                logger.info("LLM ensemble used %s (text)", name)
                return raw
        return ""


def get_llm_ensemble(config: dict) -> LLMEnsemble:
    return LLMEnsemble(config)
