"""Tests for lab traffic API."""

from unittest.mock import patch

import pytest

from app.services.lab import traffic_runner
from app.services.lab.patterns import ALL_LAB_PATTERNS


@pytest.fixture
def app_client(app):
    app.config["CAPTURE_LAB_ENABLED"] = True
    return app.test_client()


def test_lab_status_when_idle(app_client):
    with patch.object(traffic_runner, "lab_status", return_value={"running": False, "log": [], "patterns_queue": []}):
        res = app_client.get("/api/lab/status")
    assert res.status_code == 200
    assert res.get_json()["running"] is False


def test_lab_start_disabled(app):
    app.config["CAPTURE_LAB_ENABLED"] = False
    client = app.test_client()
    res = client.post("/api/lab/start", json={"patterns": ["bot"]})
    assert res.status_code == 403


def test_lab_start_all_patterns_default(app_client, monkeypatch):
    captured = {}

    def fake_start(script, patterns, iface, rotate_sec=None):
        captured["patterns"] = patterns
        captured["rotate_sec"] = rotate_sec
        return {"ok": True, "patterns": ALL_LAB_PATTERNS, "interface": iface, "pid": 1}

    monkeypatch.setattr("app.services.lab.traffic_runner.start_lab_traffic", fake_start)
    res = app_client.post("/api/lab/start", json={})
    assert res.status_code == 201
    assert captured["patterns"] is None
    assert captured["rotate_sec"] == 12


def test_pattern_rows_active():
    traffic_runner._state.update({
        "patterns": ["bot", "ddos"],
        "current_pattern": "bot",
        "pattern_started_at": __import__("time").time() - 2,
        "rotate_sec": 8,
    })
    rows = traffic_runner._pattern_rows()
    assert rows[0]["status"] == "active"
    assert rows[0]["cic_label"] == "Bot"


def test_resolve_pattern_all():
    cli, lst = traffic_runner._resolve_pattern_arg(None)
    assert cli == "all"
    assert len(lst) == 13
    assert "arp" in lst
