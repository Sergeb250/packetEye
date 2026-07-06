"""Tests for LLM ensemble orchestration."""

from unittest.mock import MagicMock, patch

from app.services.llm.ensemble import LLMEnsemble, _is_big_task


def test_is_big_task_prefixes():
    assert _is_big_task("live_alert:abc")
    assert _is_big_task("exec:123")
    assert not _is_big_task("other:xyz")


def test_ensemble_fallback_chain_uses_secondary():
    config = {
        "LLM_PROVIDER": "nvidia",
        "NVIDIA_API_KEY": "key",
        "LLM_MODEL": "deepseek-ai/deepseek-v4-pro",
        "LLM_SECONDARY_MODEL": "z-ai/glm-5.2",
        "LLM_ENSEMBLE_ENABLED": True,
        "LLM_ENSEMBLE_PARALLEL": False,
        "LLM_TIMEOUT_SECONDS": 45,
    }
    ensemble = LLMEnsemble(config)
    ensemble.primary = MagicMock()
    ensemble.primary.complete.return_value = "{}"
    ensemble.secondary = MagicMock()
    ensemble.secondary.complete.return_value = '{"summary": "ok", "confidence": 0.9}'
    ensemble.fallback = None

    result = ensemble.complete_json("sys", "user", cache_prefix="finding:x")
    assert result.get("summary") == "ok"


def test_ensemble_parallel_synthesis_single_draft():
    config = {
        "LLM_PROVIDER": "nvidia",
        "NVIDIA_API_KEY": "key",
        "LLM_MODEL": "m1",
        "LLM_SECONDARY_MODEL": "m2",
        "LLM_ENSEMBLE_ENABLED": True,
        "LLM_ENSEMBLE_PARALLEL": True,
    }
    ensemble = LLMEnsemble(config)

    with patch.object(ensemble, "_parallel_raw", return_value=[("primary", '{"verdict": "malicious"}')]):
        result = ensemble.complete_json("sys", "user", cache_prefix="live_alert:1")
    assert result.get("verdict") == "malicious"
