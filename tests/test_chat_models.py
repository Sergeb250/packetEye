"""Tests for chat model list, tier resolution, and model allowlist."""

from unittest.mock import MagicMock, patch

import pytest

from app.services.llm.chat import resolve_detail_tier
from app.services.llm.provider import NVIDIAProvider, provider_for_model
from app.services.llm.stack import is_allowed_chat_model, parse_chat_models


def test_parse_chat_models_deduplicates():
    cfg = {
        "LLM_MODEL": "minimaxai/minimax-m3",
        "LLM_CHAT_MODELS": "minimaxai/minimax-m3, meta/llama-3.1-8b-instruct",
    }
    assert parse_chat_models(cfg) == [
        "minimaxai/minimax-m3",
        "meta/llama-3.1-8b-instruct",
    ]


def test_is_allowed_chat_model():
    cfg = {"LLM_CHAT_MODELS": "minimaxai/minimax-m3,meta/llama-3.1-8b-instruct"}
    assert is_allowed_chat_model(cfg, "minimaxai/minimax-m3")
    assert not is_allowed_chat_model(cfg, "unknown/model")


def test_resolve_detail_tier_auto_brief():
    assert resolve_detail_tier("auto", "What is the top risk?") == "brief"


def test_resolve_detail_tier_auto_detailed_on_report_page():
    assert resolve_detail_tier("auto", "What is the top risk?", report_page=True) == "detailed"


def test_resolve_detail_tier_auto_detailed_on_keywords():
    assert resolve_detail_tier("auto", "Please explain more about this C2") == "detailed"
    assert resolve_detail_tier("auto", "Show me a diagram of the attack path") == "detailed"


def test_provider_for_model():
    cfg = {
        "NVIDIA_API_KEY": "nv-test",
        "NVIDIA_API_BASE": "https://integrate.api.nvidia.com/v1",
        "LLM_MAX_TOKENS": 512,
    }
    prov = provider_for_model(cfg, "meta/llama-3.1-8b-instruct", max_tokens=128)
    assert isinstance(prov, NVIDIAProvider)
    assert prov.model == "meta/llama-3.1-8b-instruct"
    assert prov.max_tokens == 128


def test_llm_models_endpoint(app):
    app.config["LLM_ENABLED"] = True
    app.config["LLM_MODEL"] = "minimaxai/minimax-m3"
    app.config["LLM_CHAT_MODELS"] = "minimaxai/minimax-m3,meta/llama-3.1-8b-instruct"
    client = app.test_client()
    res = client.get("/api/llm/models")
    assert res.status_code == 200
    data = res.get_json()
    assert data["default"] == "minimaxai/minimax-m3"
    assert "minimaxai/minimax-m3" in data["models"]


def test_chat_rejects_unknown_model(app):
    app.config["LLM_ENABLED"] = True
    app.config["NVIDIA_API_KEY"] = "nv-test"
    app.config["LLM_CHAT_MODELS"] = "minimaxai/minimax-m3"
    client = app.test_client()
    res = client.post("/api/chat", json={"message": "hello", "model": "bad/model"})
    assert res.status_code == 400
    assert "Unknown model" in res.get_json().get("error", "")


@patch("app.services.llm.chat.provider_for_model")
def test_chat_uses_brief_tier_by_default(mock_provider_for_model, app):
    app.config["LLM_ENABLED"] = True
    app.config["NVIDIA_API_KEY"] = "nv-test"
    app.config["LLM_MODEL"] = "minimaxai/minimax-m3"
    app.config["LLM_CHAT_MODELS"] = "minimaxai/minimax-m3"
    mock_prov = MagicMock()
    mock_prov.complete.return_value = "Brief answer. Ask for more detail."
    mock_provider_for_model.return_value = mock_prov

    client = app.test_client()
    res = client.post("/api/chat", json={"message": "top risks?", "model": "minimaxai/minimax-m3"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["detail_tier"] == "brief"
    assert "Brief answer" in data["reply"]
    system_arg = mock_prov.complete.call_args[0][0]
    assert "no headings" in system_arg.lower() or "2-4 short sentences" in system_arg.lower()
