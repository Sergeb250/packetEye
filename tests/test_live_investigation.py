"""Tests for live OSINT and alert investigation routes."""

from unittest.mock import patch

import pytest

from app.services.live.live_investigation import (
    extract_targets_from_alert,
    get_live_alert,
    investigate_live_alert_sync,
)
from app.services.streams import get_alert_writer, init_streams


@pytest.fixture
def stream_app(flask_app, tmp_path):
    flask_app.config["STREAM_DATA_DIR"] = str(tmp_path / "streams")
    init_streams(dict(flask_app.config))
    return flask_app


def test_extract_targets_from_alert():
    targets = extract_targets_from_alert({
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "tls_sni": "example.com",
    })
    values = {t["value"] for t in targets}
    assert "8.8.8.8" in values
    assert "example.com" in values
    # Private RFC1918 may still be listed; public filter applies at lookup time
    assert any(t["type"] == "ip" for t in targets)


def test_live_osint_returns_json_not_html(stream_app):
    with stream_app.app_context():
        with patch(
            "app.services.live.live_investigation.investigate_target_sync",
            return_value={
                "ok": True,
                "value": "8.8.8.8",
                "is_malicious": False,
                "confidence": 0.1,
                "enrichment_json": {},
                "verdict_breakdown": [],
            },
        ):
            client = stream_app.test_client()
            res = client.post(
                "/api/live/osint/live-session-uuid/8.8.8.8",
                json={"summarize": False},
            )
            assert res.status_code == 200
            assert res.content_type.startswith("application/json")
            data = res.get_json()
            assert data["ok"] is True


def test_live_investigate_alert_persists(stream_app):
    session_id = "sess-test-1"
    alert_id = "alert-abc"
    with stream_app.app_context():
        writer = get_alert_writer()
        assert writer is not None
        writer.write({
            "id": alert_id,
            "session_id": session_id,
            "timestamp": 1.0,
            "dst_ip": "1.1.1.1",
            "src_ip": "10.0.0.1",
        })
        with patch(
            "app.services.live.live_investigation.InvestigationService.run",
            return_value={
                "1.1.1.1": {
                    "type": "ip",
                    "results": {"virustotal": {"malicious": 0}},
                    "is_malicious": False,
                    "confidence": 0.0,
                    "verdict_breakdown": [],
                }
            },
        ):
            result = investigate_live_alert_sync(dict(stream_app.config), session_id, alert_id)
            assert result["ok"] is True
            assert result["investigation"]["status"] == "complete"
        alert = get_live_alert(session_id, alert_id)
        assert alert.get("investigation", {}).get("status") == "complete"
