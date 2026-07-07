"""Tests for LLM provider stack building."""

from app.services.llm.stack import build_live_stack, parse_chat_models, stack_model_names


def test_parse_chat_models_includes_default():
    cfg = {"LLM_MODEL": "minimaxai/minimax-m3", "LLM_CHAT_MODELS": "meta/llama-3.1-8b-instruct"}
    models = parse_chat_models(cfg)
    assert models[0] == "minimaxai/minimax-m3"
    assert "meta/llama-3.1-8b-instruct" in models


def test_nvidia_only_stack():
    cfg = {
        "LLM_SINGLE_PROVIDER": "nvidia",
        "NVIDIA_API_KEY": "nv-test",
        "LLM_MODEL": "deepseek-ai/deepseek-v4-pro",
        "ZAI_API_KEY": "should-not-be-used",
        "OPENROUTER_API_KEY": "should-not-be-used",
        "LLM_SECONDARY_MODEL": "z-ai/glm-5.2",
    }
    stack = build_live_stack(cfg, max_models=3)
    assert len(stack) == 1
    assert stack[0][0] == "nvidia"
    assert stack[0][1].model == "deepseek-ai/deepseek-v4-pro"
    assert stack_model_names(cfg) == ["deepseek-ai/deepseek-v4-pro"]


def test_zai_only_stack():
    cfg = {
        "LLM_SINGLE_PROVIDER": "zai",
        "ZAI_API_KEY": "z-test",
        "ZAI_MODEL": "glm-4.7-flash",
        "NVIDIA_API_KEY": "should-not-be-used",
    }
    stack = build_live_stack(cfg, max_models=3)
    assert len(stack) == 1
    assert stack[0][0] == "zai"
    assert stack[0][1].model == "glm-4.7-flash"
