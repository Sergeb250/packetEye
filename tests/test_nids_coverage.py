"""Tests for pattern coverage tracking in NIDS soak test."""

from app.services.lab.nids_test_runner import update_pattern_coverage, _init_coverage


def test_coverage_marks_ml_on_alert_increase():
    coverage = _init_coverage()
    window = None
    window, coverage = update_pattern_coverage(
        coverage,
        window,
        session_id="s1",
        started_at=0,
        current_pattern="portscan",
        prev_pattern=None,
        alert_ml=0,
        alert_suri=0,
    )
    window, coverage = update_pattern_coverage(
        coverage,
        window,
        session_id="s1",
        started_at=0,
        current_pattern="portscan",
        prev_pattern="portscan",
        alert_ml=1,
        alert_suri=0,
    )
    assert coverage["portscan"]["alerted_ml"] is True
    assert coverage["portscan"]["alerted_suricata"] is False


def test_coverage_marks_completed_on_pattern_change():
    coverage = _init_coverage()
    window = {"pattern": "portscan", "ml_at_start": 0, "suri_at_start": 0, "started_at": 0}
    window, coverage = update_pattern_coverage(
        coverage,
        window,
        session_id="s1",
        started_at=0,
        current_pattern="bot",
        prev_pattern="portscan",
        alert_ml=2,
        alert_suri=1,
    )
    assert coverage["portscan"]["completed"] is True
    assert window["pattern"] == "bot"


def test_init_coverage_includes_arp():
    coverage = _init_coverage()
    assert "arp" in coverage
    assert len(coverage) == 13
