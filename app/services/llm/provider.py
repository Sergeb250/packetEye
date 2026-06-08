"""LLM provider abstraction."""

import json
import logging
import re
import time

logger = logging.getLogger(__name__)


class LLMProvider:
    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        raise NotImplementedError


class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        if not self.api_key:
            return "{}"
        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.api_key)
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
    ):
        self.api_key = api_key
        self.model = model or self.DEFAULT_MODEL
        self.base_url = base_url or self.DEFAULT_BASE_URL
        self.max_tokens = max_tokens

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        if not self.api_key:
            return "{}"
        try:
            from openai import OpenAI

            client = OpenAI(base_url=self.base_url, api_key=self.api_key)
            # Disable DeepSeek V4 "thinking" mode for reliable JSON output
            extra_body = {"chat_template_kwargs": {"thinking": False}}
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=self.max_tokens,
                extra_body=extra_body,
            )
            return response.choices[0].message.content or "{}"
        except Exception as exc:
            logger.error("NVIDIA NIM call failed: %s", exc)
            return "{}"


class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self.api_key = api_key
        self.model = model

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        if not self.api_key:
            return "{}"
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)
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


def get_provider(config: dict) -> LLMProvider:
    provider = config.get("LLM_PROVIDER", "nvidia").lower()
    api_key = config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY", "")
    model = config.get("LLM_MODEL", NVIDIAProvider.DEFAULT_MODEL)
    base_url = config.get("NVIDIA_API_BASE", NVIDIAProvider.DEFAULT_BASE_URL)
    max_tokens = int(config.get("LLM_MAX_TOKENS", 2048))

    if provider == "anthropic":
        return AnthropicProvider(api_key, model)
    if provider == "openai":
        return OpenAIProvider(api_key, model)
    if provider == "nvidia":
        return NVIDIAProvider(api_key, model, base_url, max_tokens)
    return NVIDIAProvider(api_key, model, base_url, max_tokens)


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


def complete_with_retry(provider: LLMProvider, system: str, user: str, temperature: float = 0.2, retries: int = 3) -> dict:
    for attempt in range(retries):
        raw = provider.complete(system, user, temperature)
        parsed = parse_json_response(raw)
        if parsed:
            return parsed
        time.sleep(2 ** attempt)
    return {}
