"""Tests for LLM connectivity probe."""

from unittest.mock import MagicMock, patch

from app.services.llm.connectivity import probe_llm_connectivity


def test_connectivity_requires_api_key(app):
    with app.app_context():
        app.config["LLM_ENABLED"] = True
        app.config["NVIDIA_API_KEY"] = ""
        app.config["LLM_API_KEY"] = ""
        result = probe_llm_connectivity(dict(app.config))
        assert result["ok"] is False
        assert "API key" in result["error"] or "NVIDIA" in result["error"]


@patch("app.services.llm.connectivity.get_provider")
@patch("app.services.llm.connectivity._build_secondary")
def test_connectivity_parallel_ok(mock_secondary, mock_primary, app):
    primary = MagicMock()
    primary.complete.return_value = '{"status":"ok"}'
    primary.model = "deepseek-ai/deepseek-v4-pro"
    secondary = MagicMock()
    secondary.complete.return_value = '{"status":"ok"}'
    secondary.model = "z-ai/glm-5.2"
    mock_primary.return_value = primary
    mock_secondary.return_value = secondary

    with app.app_context():
        app.config["LLM_ENABLED"] = True
        app.config["NVIDIA_API_KEY"] = "nvapi-test"
        app.config["LLM_SECONDARY_MODEL"] = "z-ai/glm-5.2"
        result = probe_llm_connectivity(dict(app.config))

    assert result["ok"] is True
    assert result["results"]["primary"]["ok"] is True
    assert result["results"]["secondary"]["ok"] is True
