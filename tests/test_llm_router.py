"""Tests for ModelRouter task preferences."""

from unittest.mock import MagicMock, patch

from app.services.llm.router import ModelRouter, TASK_PREFERENCES


def test_task_preferences_include_zai_first_for_triage():
    assert TASK_PREFERENCES["live_triage"][0] == "zai"


@patch("app.services.llm.router.build_live_stack")
def test_router_parallel_triage(mock_stack):
    zai = MagicMock()
    zai.label = "zai"
    zai._complete_inner.return_value = '{"suspicious": false, "summary": "ok"}'
    nvidia = MagicMock()
    nvidia.label = "nvidia"
    nvidia._complete_inner.return_value = '{"suspicious": false, "summary": "nvidia ok"}'
    mock_stack.return_value = [("zai", zai), ("nvidia", nvidia)]

    router = ModelRouter({"ZAI_API_KEY": "z", "NVIDIA_API_KEY": "n"})
    outputs, errors = router.parallel_triage("sys", "user")
    assert "zai" in outputs or "nvidia" in outputs
