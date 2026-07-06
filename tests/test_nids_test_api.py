"""Tests for NIDS soak test API."""

import importlib
from unittest.mock import patch

import pytest

importlib.import_module("app.services.lab.nids_test_runner")


@pytest.fixture
def app_client(app):
    app.config["LIVE_MONITOR_ENABLED"] = True
    app.config["CAPTURE_LAB_ENABLED"] = True
    app.config["LAB_ROTATE_SEC"] = 12
    return app.test_client()


def test_nids_test_status_idle(app_client):
    with patch(
        "app.services.lab.nids_test_runner.nids_soak_status",
        return_value={"running": False, "stats": {}, "log": [], "pattern_coverage": []},
    ):
        res = app_client.get("/api/nids-test/status")
    assert res.status_code == 200
    assert res.get_json()["running"] is False


def test_nids_test_start_disabled(app):
    app.config["LIVE_MONITOR_ENABLED"] = False
    client = app.test_client()
    with patch(
        "app.services.lab.nids_test_runner.start_nids_soak",
        return_value={"ok": False, "error": "Live monitor disabled. Set LIVE_MONITOR_ENABLED=true in .env"},
    ):
        res = client.post("/api/nids-test/start", json={"mode": "suricata"})
    assert res.status_code == 403


def test_nids_test_start_ok(app_client):
    with patch(
        "app.services.lab.nids_test_runner.start_nids_soak",
        return_value={
            "ok": True,
            "session_id": "abc",
            "mode": "suricata",
            "pattern_count": 13,
            "patterns": ["portscan", "arp"],
        },
    ) as mock_start:
        res = app_client.post("/api/nids-test/start", json={"with_lab": True, "rotate_sec": 12})
    assert res.status_code == 201
    assert res.get_json()["session_id"] == "abc"
    mock_start.assert_called_once()
    assert mock_start.call_args.kwargs.get("rotate_sec") == 12


def test_nids_test_stop(app_client):
    with patch(
        "app.services.lab.nids_test_runner.stop_nids_soak",
        return_value={"ok": True, "message": "stopped", "pattern_coverage": []},
    ):
        res = app_client.post("/api/nids-test/stop", json={"stop_live": False})
    assert res.status_code == 200
    assert res.get_json()["ok"] is True
