"""Tests for LLM provider factory."""

import pytest

from app.services.llm.provider import NVIDIAProvider, get_provider


def test_get_provider_nvidia_default():
    config = {
        "LLM_PROVIDER": "nvidia",
        "NVIDIA_API_KEY": "test-key",
        "LLM_MODEL": "deepseek-ai/deepseek-v4-pro",
        "NVIDIA_API_BASE": "https://integrate.api.nvidia.com/v1",
    }
    provider = get_provider(config)
    assert isinstance(provider, NVIDIAProvider)
    assert provider.model == "deepseek-ai/deepseek-v4-pro"
    assert provider.base_url == "https://integrate.api.nvidia.com/v1"


def test_nvidia_provider_no_key_returns_empty_json():
    provider = NVIDIAProvider(api_key="")
    result = provider.complete("system", "user")
    assert result == "{}"
