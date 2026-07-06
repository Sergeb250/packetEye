"""Tests for Z.ai provider and live model stack."""

from app.services.llm.provider import ZAIProvider, get_provider
from app.services.llm.stack import build_live_stack


def test_zai_provider_defaults():
    p = ZAIProvider("test-key")
    assert p.model == ZAIProvider.DEFAULT_MODEL
    assert "api.z.ai" in p.base_url


def test_get_provider_zai():
    cfg = {"LLM_PROVIDER": "zai", "ZAI_API_KEY": "k", "ZAI_MODEL": "glm-4-flash"}
    p = get_provider(cfg)
    assert isinstance(p, ZAIProvider)
    assert p.model == "glm-4-flash"


def test_build_live_stack_three():
    cfg = {
        "ZAI_API_KEY": "z",
        "ZAI_MODEL": "glm-4-flash",
        "NVIDIA_API_KEY": "n",
        "LLM_MODEL": "deepseek-ai/deepseek-v4-pro",
        "LLM_SECONDARY_MODEL": "z-ai/glm-5.2",
        "OPENROUTER_API_KEY": "o",
    }
    stack = build_live_stack(cfg, max_models=3)
    assert len(stack) == 3
    assert stack[0][0] == "zai"
