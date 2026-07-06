"""Tests for LLM context builder."""

from app.models.analysis import Analysis, Finding, Flow
from app.services.llm.context_builder import build_rich_context, truncate_json


def test_truncate_json():
    long = {"x": "y" * 5000}
    out = truncate_json(long, max_chars=100)
    assert "[truncated" in out


def test_build_rich_context_with_finding(flask_app):
    with flask_app.app_context():
        from app.extensions import db

        a = Analysis(filename="t.pcap", file_path="/tmp/t.pcap", status="complete")
        db.session.add(a)
        db.session.flush()
        flow = Flow(
            analysis_id=a.id,
            src_ip="10.0.0.5",
            dst_ip="8.8.8.8",
            src_port=45000,
            dst_port=443,
            protocol="TCP",
            anomaly_score=6.2,
        )
        db.session.add(flow)
        db.session.flush()
        f = Finding(
            analysis_id=a.id,
            flow_id=flow.id,
            rule_id="ML-001",
            source="ml",
            title="Test anomaly",
            severity="medium",
            severity_score=6.2,
            evidence={"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "anomaly_score": 6.2},
        )
        db.session.add(f)
        db.session.commit()

        ctx = build_rich_context(analysis_id=a.id, finding_id=f.id)
        assert "FOCUSED FINDING" in ctx
        assert "8.8.8.8" in ctx
        assert "flow" in ctx.lower()

        db.session.delete(f)
        db.session.delete(flow)
        db.session.delete(a)
        db.session.commit()
