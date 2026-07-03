"""Unified severity scoring."""

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


def severity_to_score(severity: str) -> float:
    return SEVERITY_WEIGHTS.get(severity, 5.0)


def compute_analysis_risk_score(findings: list) -> float:
    if not findings:
        return 0.0
    active = [f for f in findings if not getattr(f, "is_false_positive", False)]
    if not active:
        return 0.0
    scores = [getattr(f, "severity_score", severity_to_score(getattr(f, "severity", "medium"))) for f in active]
    top = sorted(scores, reverse=True)[:5]
    weighted = sum(top) / len(top)
    return min(10.0, round(weighted, 2))


# Calibrated anomaly scale puts the Isolation Forest decision boundary at 5.0.
ML_ANOMALY_BOUNDARY = 5.0


def compute_hybrid_flow_severity(anomaly_score: float, findings: list, ml_boundary: float = ML_ANOMALY_BOUNDARY) -> float:
    """Combine ML anomaly score with rule/TI finding severities for a flow."""
    if not findings:
        return min(10.0, round(anomaly_score, 2))
    rule_scores = [
        getattr(f, "severity_score", severity_to_score(getattr(f, "severity", "medium")))
        for f in findings
        if getattr(f, "source", "") in ("rule", "ti_correlation", "suricata", "suricata_ml_correlation")
    ]
    ml_boost = anomaly_score * 0.4 if anomaly_score >= ml_boundary else 0
    base = max([anomaly_score] + rule_scores) if rule_scores else anomaly_score
    return min(10.0, round(base + ml_boost * 0.25, 2))
