"""LLM provider abstraction."""

import json
import logging
import re
import time

from app.services.llm.rate_limit import (
    affordable_max_tokens,
    llm_call_slot,
    note_failure,
)

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 45


class LLMProvider:
    label: str = "llm"

    def _complete_inner(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        raise NotImplementedError

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        max_attempts = 2
        tokens = getattr(self, "max_tokens", 512)
        for attempt in range(max_attempts):
            with llm_call_slot(self.label):
                try:
                    raw = self._complete_inner(system_prompt, user_prompt, temperature)
                    if raw and raw.strip() not in ("", "{}"):
                        return raw.strip()
                    return raw or "{}"
                except Exception as exc:
                    note_failure(self.label, exc)
                    afford = affordable_max_tokens(exc, tokens)
                    if afford and afford < tokens and attempt < max_attempts - 1:
                        logger.info("Retrying %s with max_tokens=%s (credit/rate limit)", self.label, afford)
                        self.max_tokens = afford
                        tokens = afford
                        time.sleep(1.5)
                        continue
                    logger.error("%s call failed: %s", self.label, exc)
                    return "{}"
        return "{}"


class OpenAIProvider(LLMProvider):
    label = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o", timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_tokens = 1024

    def _complete_inner(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        if not self.api_key:
            return "{}"
        from openai import OpenAI

        client = OpenAI(api_key=self.api_key, timeout=self.timeout, max_retries=0)
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=self.max_tokens,
        )
        return response.choices[0].message.content or "{}"


class ZAIProvider(LLMProvider):
    """Z.ai (Zhipu) GLM — OpenAI-compatible API (primary for live analysis)."""

    label = "zai"
    DEFAULT_BASE_URL = "https://api.z.ai/api/paas/v4/"
    DEFAULT_MODEL = "glm-4-flash"

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        base_url: str | None = None,
        max_tokens: int = 512,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.api_key = api_key
        self.model = model or self.DEFAULT_MODEL
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/") + "/"
        self.max_tokens = max_tokens
        self.timeout = timeout

    def _complete_inner(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        if not self.api_key:
            return "{}"
        from openai import OpenAI

        client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.timeout,
            max_retries=0,
        )
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=self.max_tokens,
            extra_headers={"Accept-Language": "en-US,en"},
        )
        return response.choices[0].message.content or "{}"


class NVIDIAProvider(LLMProvider):
    """NVIDIA NIM — OpenAI-compatible API (DeepSeek, etc.)."""

    label = "nvidia"
    DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
    DEFAULT_MODEL = "deepseek-ai/deepseek-v4-pro"

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        base_url: str | None = None,
        max_tokens: int = 512,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.api_key = api_key
        self.model = model or self.DEFAULT_MODEL
        self.base_url = base_url or self.DEFAULT_BASE_URL
        self.max_tokens = max_tokens
        self.timeout = timeout

    def _complete_inner(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        if not self.api_key:
            return "{}"
        from openai import OpenAI

        client = OpenAI(
            base_url=self.base_url, api_key=self.api_key,
            timeout=self.timeout, max_retries=0,
        )
        kwargs: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": self.max_tokens,
        }
        if "deepseek" in self.model.lower():
            kwargs["extra_body"] = {"chat_template_kwargs": {"thinking": False}}
        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or "{}"


class AnthropicProvider(LLMProvider):
    label = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6", timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_tokens = 1024

    def _complete_inner(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        if not self.api_key:
            return "{}"
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout, max_retries=0)
        response = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=temperature,
        )
        return response.content[0].text if response.content else "{}"


class OpenRouterProvider(LLMProvider):
    """OpenRouter — fallback when primary models fail."""

    label = "openrouter"
    DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(
        self,
        api_key: str,
        model: str = "deepseek/deepseek-chat",
        base_url: str | None = None,
        max_tokens: int = 256,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url or self.DEFAULT_BASE_URL
        self.max_tokens = max_tokens
        self.timeout = timeout

    def _complete_inner(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        if not self.api_key:
            return "{}"
        from openai import OpenAI

        client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.timeout,
            max_retries=0,
        )
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=self.max_tokens,
        )
        return response.choices[0].message.content or "{}"


def get_provider(config: dict) -> LLMProvider:
    provider = config.get("LLM_PROVIDER", "zai").lower()
    max_tokens = int(config.get("LLM_MAX_TOKENS", 512))
    timeout = float(config.get("LLM_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))

    if provider == "zai":
        key = (config.get("ZAI_API_KEY") or "").strip()
        if not key:
            provider = "nvidia"
        else:
            return ZAIProvider(
                key,
                config.get("ZAI_MODEL", ZAIProvider.DEFAULT_MODEL),
                config.get("ZAI_API_BASE", ZAIProvider.DEFAULT_BASE_URL),
                max_tokens,
                timeout,
            )

    api_key = config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY", "")
    model = config.get("LLM_MODEL", NVIDIAProvider.DEFAULT_MODEL)
    base_url = config.get("NVIDIA_API_BASE", NVIDIAProvider.DEFAULT_BASE_URL)

    if provider == "anthropic":
        p = AnthropicProvider(api_key, model, timeout=timeout)
        p.max_tokens = max_tokens
        return p
    if provider == "openai":
        p = OpenAIProvider(api_key, model, timeout=timeout)
        p.max_tokens = max_tokens
        return p
    return NVIDIAProvider(api_key, model, base_url, max_tokens, timeout=timeout)


def parse_json_response(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return {}


def complete_with_retry(provider: LLMProvider, system: str, user: str, temperature: float = 0.2, retries: int = 2) -> dict:
    for attempt in range(retries):
        raw = provider.complete(system, user, temperature)
        parsed = parse_json_response(raw)
        if parsed:
            return parsed
        if attempt < retries - 1:
            time.sleep(1)
    return {}
