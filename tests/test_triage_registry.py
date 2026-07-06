"""Tests for unified triage incident registry."""

from app.services.live.triage_registry import (
    build_incident_row,
    list_incidents,
    register_from_alert,
    set_verdict,
    upsert_incident,
)


def test_build_incident_row_normalizes_sources():
    row = build_incident_row(
        session_id="sess-1",
        src_ip="10.0.0.1",
        dst_ip="203.0.113.5",
        dst_port=22,
        sources=["llm", "heuristic"],
        attack_type="SSH-Patator",
        disposition="open",
    )
    assert "llm" in row["sources"]
    assert "heuristic" in row["sources"]
    assert row["id"]


def test_upsert_merges_same_connection(flask_app):
    with flask_app.app_context():
        sid = "merge-test"
        a = build_incident_row(
            session_id=sid,
            src_ip="10.0.0.2",
            dst_ip="203.0.113.10",
            dst_port=22,
            sources=["heuristic"],
            attack_type="SSH-Patator",
            disposition="open",
        )
        upsert_incident(sid, a)
        b = build_incident_row(
            session_id=sid,
            src_ip="10.0.0.2",
            dst_ip="203.0.113.10",
            dst_port=22,
            sources=["llm"],
            attack_type="SSH-Patator",
            disposition="open",
            llm_merged_summary="dual-model agree",
        )
        merged = upsert_incident(sid, b)
        assert "heuristic" in merged["sources"]
        assert "llm" in merged["sources"]
        rows = list_incidents(sid)
        assert len(rows) == 1


def test_list_incidents_filters(flask_app):
    with flask_app.app_context():
        sid = "filter-test"
        upsert_incident(
            sid,
            build_incident_row(
                session_id=sid,
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
                sources=["llm"],
                disposition="true_negative",
                attack_type="BENIGN",
            ),
        )
        upsert_incident(
            sid,
            build_incident_row(
                session_id=sid,
                src_ip="3.3.3.3",
                dst_ip="4.4.4.4",
                sources=["suricata"],
                disposition="open",
                attack_type="PortScan",
            ),
        )
        tn = list_incidents(sid, disposition="true_negative")
        assert len(tn) == 1
        assert tn[0]["attack_type"] == "BENIGN"
        sur = list_incidents(sid, source="suricata")
        assert len(sur) == 1


def test_register_from_alert(flask_app):
    with flask_app.app_context():
        sid = "alert-reg"
        alert = {
            "id": "a1",
            "type": "suricata",
            "timestamp": 1000.0,
            "severity": "high",
            "signature": "SSH brute",
            "src_ip": "203.0.113.1",
            "dst_ip": "192.168.1.1",
            "dst_port": 22,
            "protocol": "TCP",
        }
        row = register_from_alert(sid, alert)
        assert "suricata" in row["sources"]
        assert row["attack_type"] == "SSH brute"


def test_ring_buffer_caps_at_500(flask_app):
    with flask_app.app_context():
        sid = "ring-test"
        for i in range(510):
            upsert_incident(
                sid,
                build_incident_row(
                    session_id=sid,
                    src_ip=f"10.0.0.{i % 250}",
                    dst_ip=f"10.0.1.{i}",
                    dst_port=i + 1,
                    sources=["llm"],
                    disposition="open",
                ),
            )
        rows = list_incidents(sid, limit=600)
        assert len(rows) <= 500
