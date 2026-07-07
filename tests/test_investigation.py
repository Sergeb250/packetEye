"""Tests for alert-driven investigation target extraction + correlation + webhook gating."""

import time
from types import SimpleNamespace

from app.services.investigation.service import extract_targets
from app.services.integrations.store import save_discord_config
from app.services.live.correlation import LiveCorrelator
from app.services.live.webhook_notifier import WebhookNotifier


def _finding(evidence, flow_id=None):
    return SimpleNamespace(evidence=evidence, flow_id=flow_id)


def test_extract_targets_public_ip_and_domain():
    finding = _finding(
        {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "tls_sni": "evil.example.com"}
    )
    targets = extract_targets(finding)
    values = {t["value"] for t in targets}
    assert "8.8.8.8" in values
    assert "evil.example.com" in values
    # private src IP is still listed but flagged non-public
    src = next(t for t in targets if t["value"] == "10.0.0.5")
    assert src["public"] is False
    ext = next(t for t in targets if t["value"] == "8.8.8.8")
    assert ext["public"] is True


def test_extract_targets_dedupes_and_caps():
    finding = _finding({"src_ip": "1.1.1.1", "dst_ip": "1.1.1.1", "ip": "1.1.1.1"})
    targets = extract_targets(finding)
    assert len([t for t in targets if t["value"] == "1.1.1.1"]) == 1


# --- correlation -----------------------------------------------------------

def test_correlator_matches_shared_hosts_within_window():
    corr = LiveCorrelator(window_seconds=120)
    now = time.time()
    assert corr.add_suricata(
        {"src_ip": "10.0.0.9", "dst_ip": "203.0.113.5", "signature": "ET SCAN"}, now=now
    ) == []
    matches = corr.add_ml(
        {"src_ip": "10.0.0.9", "dst_ip": "203.0.113.5"},
        {"flagged": True, "anomaly_score": 8.1},
        now=now + 5,
    )
    assert len(matches) == 1
    assert matches[0]["signature"] == "ET SCAN"
    assert matches[0]["anomaly_score"] == 8.1


def test_correlator_no_match_outside_window():
    corr = LiveCorrelator(window_seconds=60)
    now = time.time()
    corr.add_suricata({"src_ip": "10.0.0.9", "dst_ip": "203.0.113.5", "signature": "X"}, now=now)
    matches = corr.add_ml(
        {"src_ip": "10.0.0.9", "dst_ip": "203.0.113.5"},
        {"flagged": True, "anomaly_score": 7.0},
        now=now + 200,
    )
    assert matches == []


def test_correlator_ignores_unflagged_ml():
    corr = LiveCorrelator()
    corr.add_suricata({"src_ip": "a", "dst_ip": "b", "signature": "X"})
    assert corr.add_ml({"src_ip": "a", "dst_ip": "b"}, {"flagged": False}) == []


# --- webhook ---------------------------------------------------------------

def test_webhook_disabled_without_url():
    wh = WebhookNotifier({"INTEGRATIONS_CONFIG_PATH": "/nonexistent/integrations.json"})
    assert wh.enabled is False
    assert wh.notify({"severity": "critical", "type": "ml"}) is False


def test_webhook_severity_gate(tmp_path):
    path = tmp_path / "integrations.json"
    config = {"INTEGRATIONS_CONFIG_PATH": str(path)}
    save_discord_config({
        "enabled": True,
        "url": "https://example.test/hook",
        "severities": ["high", "critical"],
        "sources": ["all"],
        "ai_statuses": ["all"],
    }, config)
    wh = WebhookNotifier(config)
    dc = wh._reload()
    assert wh._passes_filters({"severity": "critical", "type": "ml"}, dc) is True
    assert wh._passes_filters({"severity": "high", "type": "ml"}, dc) is True
    assert wh._passes_filters({"severity": "medium", "type": "ml"}, dc) is False
    assert wh._passes_filters({"severity": "low", "type": "suricata"}, dc) is False


def test_webhook_rate_limit(tmp_path):
    path = tmp_path / "integrations.json"
    config = {"INTEGRATIONS_CONFIG_PATH": str(path)}
    save_discord_config({
        "enabled": True,
        "url": "https://example.test/hook",
        "severities": ["all"],
        "sources": ["all"],
        "ai_statuses": ["all"],
        "rate_limit_per_minute": 2,
    }, config)
    wh = WebhookNotifier(config)
    assert wh._allowed() is True
    assert wh._allowed() is True
    assert wh._allowed() is False
