"""Tests for Discord webhook notifier filters and payloads."""

from unittest.mock import MagicMock, patch

import pytest

from app.services.integrations.store import save_discord_config
from app.services.live.alert_service import AlertService
from app.services.live.webhook_notifier import WebhookNotifier, get_webhook_notifier


@pytest.fixture
def integrations_path(flask_app, tmp_path):
    path = tmp_path / "integrations.json"
    flask_app.config["INTEGRATIONS_CONFIG_PATH"] = str(path)
    save_discord_config({
        "enabled": True,
        "url": "https://discord.test/webhook",
        "severities": ["high", "critical"],
        "sources": ["all"],
        "ai_statuses": ["true_positive"],
        "rate_limit_per_minute": 10,
    }, dict(flask_app.config))
    return path


def test_webhook_disabled_without_url(flask_app):
    flask_app.config["INTEGRATIONS_CONFIG_PATH"] = "/nonexistent/integrations.json"
    wh = WebhookNotifier(dict(flask_app.config))
    save_discord_config({"enabled": False, "url": ""}, dict(flask_app.config))
    assert wh.enabled is False
    assert wh.notify({"severity": "critical"}) is False


def test_webhook_severity_filter(integrations_path, flask_app):
    wh = WebhookNotifier(dict(flask_app.config))
    assert wh._passes_filters({"severity": "critical", "type": "ml"}, wh._reload()) is True
    assert wh._passes_filters({"severity": "high", "type": "ml"}, wh._reload()) is True
    assert wh._passes_filters({"severity": "medium", "type": "ml"}, wh._reload()) is False
    assert wh._passes_filters({"severity": "low", "type": "suricata"}, wh._reload()) is False


def test_webhook_source_filter(integrations_path, flask_app):
    save_discord_config({
        "severities": ["all"],
        "sources": ["suricata", "llm"],
        "ai_statuses": ["all"],
    }, dict(flask_app.config))
    wh = WebhookNotifier(dict(flask_app.config))
    dc = wh._reload()
    assert wh._passes_filters({"severity": "high", "type": "suricata"}, dc) is True
    assert wh._passes_filters({"severity": "high", "type": "ml"}, dc) is False


def test_webhook_ai_status_filter(integrations_path, flask_app):
    wh = WebhookNotifier(dict(flask_app.config))
    dc = wh._reload()
    assert wh._passes_filters({"severity": "high", "type": "llm", "ai_status": "true_positive"}, dc) is True
    assert wh._passes_filters({"severity": "high", "type": "llm", "ai_status": "true_negative"}, dc) is False
    assert wh._passes_filters({"severity": "high", "type": "ml"}, dc) is True


def test_webhook_payload_titles():
    wh = WebhookNotifier({})
    llm = wh._alert_title({"type": "llm", "attack_type": "PortScan", "ai_status": "true_positive"})
    assert "AI Triage" in llm
    corr = wh._alert_title({"type": "correlation", "signature": "ET SCAN", "anomaly_score": 7.2})
    assert "Correlation" in corr


def test_webhook_rate_limit(integrations_path, flask_app):
    save_discord_config({"rate_limit_per_minute": 2}, dict(flask_app.config))
    wh = WebhookNotifier(dict(flask_app.config))
    assert wh._allowed() is True
    assert wh._allowed() is True
    assert wh._allowed() is False


def test_get_webhook_notifier(integrations_path, flask_app):
    assert get_webhook_notifier(dict(flask_app.config)) is not None
    save_discord_config({"enabled": False}, dict(flask_app.config))
    assert get_webhook_notifier(dict(flask_app.config)) is None


@patch("requests.post")
def test_emit_prepared_triggers_webhook(mock_post, integrations_path, flask_app):
    mock_post.return_value = MagicMock(status_code=204, text="")
    with flask_app.app_context():
        wh = get_webhook_notifier(dict(flask_app.config))
        svc = AlertService("sess-1", webhook=wh)
        svc.emit_prepared({
            "type": "llm",
            "severity": "critical",
            "explanation": "test",
            "ai_status": "true_positive",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
        })
    assert mock_post.called
