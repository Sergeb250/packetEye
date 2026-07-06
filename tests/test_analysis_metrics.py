"""Tests for live analysis metrics API."""


def test_analysis_metrics(flask_app):
    from app.extensions import db
    from app.models.analysis import Analysis, Finding, Observable

    with flask_app.app_context():
        a = Analysis(
            id="metrics-test-1",
            filename="test.pcap",
            file_path="/tmp/t.pcap",
            status="complete",
            risk_score=8.0,
        )
        db.session.add(a)
        db.session.add(
            Finding(
                analysis_id=a.id,
                rule_id="ml_anomaly",
                title="Test",
                severity="high",
                severity_score=8.0,
            )
        )
        db.session.add(
            Observable(
                analysis_id=a.id,
                type="ip",
                value="8.8.8.8",
                is_malicious=True,
                enrichment_status="complete",
                enrichment_json={"virustotal": {"malicious": 5}},
            )
        )
        db.session.commit()

    client = flask_app.test_client()
    res = client.get("/api/analysis/metrics-test-1/metrics")
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert data["malicious_observables"] == 1
    assert data["finding_count"] == 1
    assert data["risk_score"] >= 7.0
