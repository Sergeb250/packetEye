"""Tests for hybrid severity scoring."""

from app.services.detection.scoring import compute_hybrid_flow_severity


class FakeFinding:
    def __init__(self, source, severity_score, severity="medium"):
        self.source = source
        self.severity_score = severity_score
        self.severity = severity


def test_hybrid_severity_ml_only():
    assert compute_hybrid_flow_severity(8.0, []) == 8.0


def test_hybrid_severity_with_rule():
    findings = [FakeFinding("rule", 8.0, "high")]
    score = compute_hybrid_flow_severity(7.5, findings)
    assert score >= 8.0
