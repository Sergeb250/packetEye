"""Tests for live alert feed."""

from app.services.live.alert_service import AlertService


def test_get_alerts_since_filter(app):
    with app.app_context():
        svc = AlertService("sess-1")
        svc._push_to_feed({"id": "1", "timestamp": 10.0, "severity": "high", "type": "ml"})
        svc._push_to_feed({"id": "2", "timestamp": 20.0, "severity": "medium", "type": "ml"})
        all_alerts = AlertService.get_alerts("sess-1", since_ts=0)
        assert len(all_alerts) == 2
        recent = AlertService.get_alerts("sess-1", since_ts=15.0)
        assert len(recent) == 1
