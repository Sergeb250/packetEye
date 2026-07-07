"""Build ordered LLM provider stack: Z.ai GLM → NVIDIA → OpenRouter."""

from __future__ import annotations

from app.services.llm.provider import (
    NVIDIAProvider,
    OpenRouterProvider,
    ZAIProvider,
    get_provider,
)


def parse_chat_models(config: dict) -> list[str]:
    """Return deduplicated NIM model IDs available in the chat selector."""
    raw = config.get("LLM_CHAT_MODELS") or config.get("LLM_MODEL") or NVIDIAProvider.DEFAULT_MODEL
    models: list[str] = []
    for part in str(raw).split(","):
        mid = part.strip()
        if mid and mid not in models:
            models.append(mid)
    default = (config.get("LLM_MODEL") or NVIDIAProvider.DEFAULT_MODEL).strip()
    if default and default not in models:
        models.insert(0, default)
    return models or [NVIDIAProvider.DEFAULT_MODEL]


def is_allowed_chat_model(config: dict, model_id: str) -> bool:
    return model_id.strip() in parse_chat_models(config)


def _single_provider_mode(config: dict) -> str:
    mode = (config.get("LLM_SINGLE_PROVIDER") or "").strip().lower()
    if mode in ("zai", "nvidia"):
        return mode
    if config.get("LLM_ZAI_ONLY"):
        return "zai"
    if config.get("LLM_NVIDIA_ONLY"):
        return "nvidia"
    return ""


def _nvidia_only_stack(config: dict, timeout: float, max_tokens: int) -> list[tuple[str, object]]:
    nvidia_key = (config.get("NVIDIA_API_KEY") or config.get("LLM_API_KEY") or "").strip()
    if not nvidia_key:
        return [("primary", get_provider(config))]
    model = config.get("LLM_MODEL", NVIDIAProvider.DEFAULT_MODEL)
    return [
        (
            "nvidia",
            NVIDIAProvider(
                nvidia_key,
                model,
                config.get("NVIDIA_API_BASE", NVIDIAProvider.DEFAULT_BASE_URL),
                max_tokens,
                timeout,
            ),
        )
    ]


def _zai_only_stack(config: dict, timeout: float, max_tokens: int) -> list[tuple[str, object]]:
    zai_key = (config.get("ZAI_API_KEY") or "").strip()
    if zai_key:
        return [
            (
                "zai",
                ZAIProvider(
                    zai_key,
                    config.get("ZAI_MODEL", ZAIProvider.DEFAULT_MODEL),
                    config.get("ZAI_API_BASE", ZAIProvider.DEFAULT_BASE_URL),
                    max_tokens,
                    timeout,
                ),
            )
        ]
    if (config.get("LLM_PROVIDER") or "").lower() == "zai":
        primary = get_provider(config)
        if primary:
            return [("zai", primary)]
    return [("primary", get_provider(config))]


def build_live_stack(config: dict, *, max_models: int = 3) -> list[tuple[str, object]]:
    """Up to 3 providers for live packet triage (sequential, shared rate limit)."""
    timeout = float(config.get("LLM_LIVE_TIMEOUT_SECONDS", 18))
    max_tokens = int(config.get("LLM_MAX_TOKENS", 256))
    single = _single_provider_mode(config)
    if single == "nvidia":
        return _nvidia_only_stack(config, timeout, max_tokens)[:max_models]
    if single == "zai":
        return _zai_only_stack(config, timeout, max_tokens)[:max_models]

    stack: list[tuple[str, object]] = []

    zai_key = (config.get("ZAI_API_KEY") or "").strip()
    if zai_key:
        stack.append(
            (
                "zai",
                ZAIProvider(
                    zai_key,
                    config.get("ZAI_MODEL", ZAIProvider.DEFAULT_MODEL),
                    config.get("ZAI_API_BASE", ZAIProvider.DEFAULT_BASE_URL),
                    max_tokens,
                    timeout,
                ),
            )
        )
    elif (config.get("LLM_PROVIDER") or "").lower() == "zai":
        primary = get_provider(config)
        if primary:
            stack.append(("zai", primary))

    nvidia_key = config.get("NVIDIA_API_KEY") or config.get("LLM_API_KEY") or ""
    nvidia_model = config.get("NVIDIA_FALLBACK_MODEL") or config.get("LLM_MODEL", NVIDIAProvider.DEFAULT_MODEL)
    if nvidia_key and len(stack) < max_models:
        if not any(getattr(p, "model", None) == nvidia_model for _, p in stack):
            stack.append(
                (
                    "nvidia",
                    NVIDIAProvider(
                        nvidia_key,
                        nvidia_model,
                        config.get("NVIDIA_API_BASE", NVIDIAProvider.DEFAULT_BASE_URL),
                        int(config.get("LLM_SECONDARY_MAX_TOKENS", max_tokens)),
                        timeout,
                    ),
                )
            )

    secondary_model = (config.get("LLM_SECONDARY_MODEL") or "").strip()
    if nvidia_key and secondary_model and len(stack) < max_models:
        if not any(getattr(p, "model", None) == secondary_model for _, p in stack):
            stack.append(
                (
                    "nvidia_secondary",
                    NVIDIAProvider(
                        nvidia_key,
                        secondary_model,
                        config.get("NVIDIA_API_BASE", NVIDIAProvider.DEFAULT_BASE_URL),
                        int(config.get("LLM_SECONDARY_MAX_TOKENS", max_tokens)),
                        timeout,
                    ),
                )
            )

    or_key = (config.get("OPENROUTER_API_KEY") or "").strip()
    if or_key and config.get("OPENROUTER_ENABLED", True) and len(stack) < max_models:
        stack.append(
            (
                "openrouter",
                OpenRouterProvider(
                    or_key,
                    config.get("OPENROUTER_MODEL", "deepseek/deepseek-chat"),
                    config.get("OPENROUTER_BASE", OpenRouterProvider.DEFAULT_BASE_URL),
                    int(config.get("OPENROUTER_MAX_TOKENS", 256)),
                    timeout,
                ),
            )
        )

    if not stack:
        stack.append(("primary", get_provider(config)))

    return stack[:max_models]


def stack_model_names(config: dict) -> list[str]:
    single = _single_provider_mode(config)
    if single == "nvidia":
        return [config.get("LLM_MODEL") or NVIDIAProvider.DEFAULT_MODEL]
    if single == "zai":
        return [config.get("ZAI_MODEL") or ZAIProvider.DEFAULT_MODEL]

    names = []
    if (config.get("ZAI_API_KEY") or "").strip() or (config.get("LLM_PROVIDER") or "").lower() == "zai":
        names.append(config.get("ZAI_MODEL") or ZAIProvider.DEFAULT_MODEL)
    nvidia_model = config.get("NVIDIA_FALLBACK_MODEL") or config.get("LLM_MODEL")
    if config.get("NVIDIA_API_KEY") or config.get("LLM_API_KEY"):
        names.append(nvidia_model)
    if config.get("LLM_SECONDARY_MODEL"):
        names.append(config.get("LLM_SECONDARY_MODEL"))
    if config.get("OPENROUTER_API_KEY") and config.get("OPENROUTER_ENABLED", True):
        names.append(config.get("OPENROUTER_MODEL", "openrouter"))
    return names[:3]
