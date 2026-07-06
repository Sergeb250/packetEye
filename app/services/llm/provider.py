"""LLM provider abstraction."""

import json
import logging
import re
import time

logger = logging.getLogger(__name__)


# Hard cap per API attempt. Without this the OpenAI SDK waits up to 600s per
# attempt (with 2 internal retries) — an unreachable LLM stalls the whole
# analysis pipeline for hours.
DEFAULT_TIMEOUT_SECONDS = 45


class LLMProvider:
    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        raise NotImplementedError


class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gpt-4o", timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        if not self.api_key:
            return "{}"
        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.api_key, timeout=self.timeout, max_retries=1)
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
            )
            return response.choices[0].message.content or "{}"
        except Exception as exc:
            logger.error("OpenAI call failed: %s", exc)
            return "{}"


class NVIDIAProvider(LLMProvider):
    """NVIDIA NIM — OpenAI-compatible free-tier API (DeepSeek V4, etc.)."""

    DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
    DEFAULT_MODEL = "deepseek-ai/deepseek-v4-pro"

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        base_url: str | None = None,
        max_tokens: int = 2048,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.api_key = api_key
        self.model = model or self.DEFAULT_MODEL
        self.base_url = base_url or self.DEFAULT_BASE_URL
        self.max_tokens = max_tokens
        self.timeout = timeout

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        if not self.api_key:
            return "{}"
        try:
            from openai import OpenAI

            client = OpenAI(
                base_url=self.base_url, api_key=self.api_key,
                timeout=self.timeout, max_retries=1,
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
        except Exception as exc:
            logger.error("NVIDIA NIM call failed: %s", exc)
            return "{}"


class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6", timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        if not self.api_key:
            return "{}"
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout, max_retries=1)
            response = client.messages.create(
                model=self.model,
                max_tokens=2048,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                temperature=temperature,
            )
            return response.content[0].text if response.content else "{}"
        except Exception as exc:
            logger.error("Anthropic call failed: %s", exc)
            return "{}"


class OpenRouterProvider(LLMProvider):
    """OpenRouter — fallback when NVIDIA models fail."""

    DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(
        self,
        api_key: str,
        model: str = "deepseek/deepseek-chat",
        base_url: str | None = None,
        max_tokens: int = 2048,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url or self.DEFAULT_BASE_URL
        self.max_tokens = max_tokens
        self.timeout = timeout

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        if not self.api_key:
            return "{}"
        try:
            from openai import OpenAI

            client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
                timeout=self.timeout,
                max_retries=1,
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
        except Exception as exc:
            logger.error("OpenRouter call failed: %s", exc)
            return "{}"


def get_provider(config: dict) -> LLMProvider:
    provider = config.get("LLM_PROVIDER", "nvidia").lower()
    api_key = config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY", "")
    model = config.get("LLM_MODEL", NVIDIAProvider.DEFAULT_MODEL)
    base_url = config.get("NVIDIA_API_BASE", NVIDIAProvider.DEFAULT_BASE_URL)
    max_tokens = int(config.get("LLM_MAX_TOKENS", 2048))
    timeout = float(config.get("LLM_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))

    if provider == "anthropic":
        return AnthropicProvider(api_key, model, timeout=timeout)
    if provider == "openai":
        return OpenAIProvider(api_key, model, timeout=timeout)
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
