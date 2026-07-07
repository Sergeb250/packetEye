"""Tests for escalation email draft and send."""

from unittest.mock import patch

import pytest

from app.services.escalation.email_service import send_escalation_email


def test_send_escalation_disabled():
    result = send_escalation_email({"SMTP_ENABLED": False}, to="a@b.com", subject="s", body="b")
    assert result["ok"] is False
    assert "disabled" in result["error"].lower()


def test_send_escalation_invalid_to():
    cfg = {"SMTP_ENABLED": True, "SMTP_USER": "u", "SMTP_PASSWORD": "p"}
    result = send_escalation_email(cfg, to="not-an-email", subject="s", body="b")
    assert result["ok"] is False


@patch("app.services.escalation.email_service.smtplib.SMTP")
def test_send_escalation_success(mock_smtp):
    cfg = {
        "SMTP_ENABLED": True,
        "SMTP_USER": "user@gmail.com",
        "SMTP_PASSWORD": "app-pass",
        "SMTP_FROM": "user@gmail.com",
        "SMTP_HOST": "smtp.gmail.com",
        "SMTP_PORT": 587,
    }
    server = mock_smtp.return_value.__enter__.return_value
    result = send_escalation_email(cfg, to="lead@company.com", subject="Test", body="Body text")
    assert result["ok"] is True
    server.starttls.assert_called_once()
    server.login.assert_called_once()
    server.send_message.assert_called_once()


def test_escalation_config_endpoint(app):
    app.config["ESCALATION_DEFAULT_TO"] = "soc@example.com"
    client = app.test_client()
    res = client.get("/api/escalation/config")
    assert res.status_code == 200
    data = res.get_json()
    assert data["default_to"] == "soc@example.com"
