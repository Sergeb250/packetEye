"""Tests for LLM connectivity probe."""

from unittest.mock import MagicMock, patch

from app.services.llm.connectivity import probe_llm_connectivity


def test_connectivity_requires_api_key(app):
    with app.app_context():
        app.config["LLM_ENABLED"] = True
        app.config["NVIDIA_API_KEY"] = ""
        app.config["LLM_API_KEY"] = ""
        app.config["ZAI_API_KEY"] = ""
        result = probe_llm_connectivity(dict(app.config))
        assert result["ok"] is False
        assert "API key" in result["error"] or "ZAI" in result["error"]


@patch("app.services.llm.connectivity.build_live_stack")
def test_connectivity_stack_ok(mock_stack, app):
    zai = MagicMock()
    zai.label = "zai"
    zai._complete_inner.return_value = '{"status":"ok"}'
    zai.model = "glm-4-flash"
    nvidia = MagicMock()
    nvidia.label = "nvidia"
    nvidia._complete_inner.return_value = '{"status":"ok"}'
    nvidia.model = "deepseek-ai/deepseek-v4-pro"
    mock_stack.return_value = [("zai", zai), ("nvidia", nvidia)]

    with app.app_context():
        app.config["LLM_ENABLED"] = True
        app.config["ZAI_API_KEY"] = "zai-test"
        app.config["NVIDIA_API_KEY"] = "nvapi-test"
        result = probe_llm_connectivity(dict(app.config))

    assert result["ok"] is True
    assert result["sequential"] is True
    assert result["results"]["zai"]["ok"] is True
    assert result["results"]["nvidia"]["ok"] is True
    zai._complete_inner.assert_called_once()
    nvidia._complete_inner.assert_called_once()
