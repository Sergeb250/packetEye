"""API tests for Integrations page (Discord webhooks)."""

import pytest

from app.services.integrations.store import save_discord_config


@pytest.fixture
def integrations_client(flask_app, tmp_path):
    flask_app.config["INTEGRATIONS_CONFIG_PATH"] = str(tmp_path / "integrations.json")
    return flask_app.test_client()


def test_integrations_config_get(integrations_client, flask_app):
    save_discord_config({
        "enabled": True,
        "url": "https://discord.com/api/webhooks/1234567890/abcdefghijklmnop",
        "severities": ["high", "critical"],
        "sources": ["ml", "suricata"],
        "ai_statuses": ["true_positive"],
    }, dict(flask_app.config))

    res = integrations_client.get("/api/integrations/config")
    assert res.status_code == 200
    data = res.get_json()
    assert data["discord"]["enabled"] is True
    assert data["discord"]["url_configured"] is True
    assert "…" in data["discord"]["url_masked"]
    assert "1234567890" not in data["discord"]["url_masked"] or data["discord"]["url_masked"].startswith("https://")
    assert data["discord"]["severities"] == ["high", "critical"]


def test_integrations_discord_save(integrations_client):
    res = integrations_client.put(
        "/api/integrations/discord",
        json={
            "enabled": True,
            "url": "https://discord.com/api/webhooks/test/token",
            "severities": ["all"],
            "sources": ["suricata"],
            "ai_statuses": ["all"],
            "rate_limit_per_minute": 5,
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert data["discord"]["enabled"] is True
    assert data["discord"]["sources"] == ["suricata"]


def test_integrations_discord_save_rejects_http(integrations_client):
    res = integrations_client.put(
        "/api/integrations/discord",
        json={"url": "http://insecure.test/hook"},
    )
    assert res.status_code == 400
    assert "https" in res.get_json()["error"].lower()


def test_integrations_discord_test(integrations_client, flask_app, monkeypatch):
    save_discord_config({
        "enabled": True,
        "url": "https://discord.test/hook",
        "severities": ["all"],
        "sources": ["all"],
        "ai_statuses": ["all"],
    }, dict(flask_app.config))

    called = {}

    def fake_post(url, json, timeout):
        called["url"] = url
        class R:
            status_code = 204
            text = ""
        return R()

    monkeypatch.setattr("requests.post", fake_post)
    res = integrations_client.post("/api/integrations/discord/test")
    assert res.status_code == 200
    assert res.get_json()["ok"] is True
    assert called.get("url") == "https://discord.test/hook"
