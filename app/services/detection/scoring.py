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
