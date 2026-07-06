"""API tests for live triage endpoints."""

import uuid

import pytest

from app.extensions import db
from app.models.analysis import Analysis
from app.services.live.triage_registry import build_incident_row, upsert_incident


@pytest.fixture
def session_id(flask_app):
    with flask_app.app_context():
        sid = str(uuid.uuid4())
        db.session.add(Analysis(
            id=sid,
            filename="live-test",
            file_path="/tmp/live-test.pcap",
            source="live",
            status="running",
        ))
        db.session.commit()
        upsert_incident(
            sid,
            build_incident_row(
                session_id=sid,
                src_ip="203.0.113.1",
                dst_ip="192.168.1.1",
                dst_port=22,
                sources=["llm"],
                attack_type="SSH-Patator",
                disposition="open",
                llm_merged_summary="test summary",
            ),
        )
        yield sid


def test_triage_incidents_list(app, session_id):
    client = app.test_client()
    res = client.get(f"/api/live/triage/incidents?session_id={session_id}")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] >= 1
    assert data["incidents"][0]["attack_type"] == "SSH-Patator"


def test_triage_status(app, session_id):
    client = app.test_client()
    res = client.get(f"/api/live/triage/status?session_id={session_id}")
    assert res.status_code == 200
    data = res.get_json()
    assert "registry" in data
    assert data["registry"]["total"] >= 1


def test_triage_verdict(app, session_id):
    client = app.test_client()
    list_res = client.get(f"/api/live/triage/incidents?session_id={session_id}")
    incident_id = list_res.get_json()["incidents"][0]["id"]
    res = client.post(
        "/api/live/triage/verdict",
        json={"session_id": session_id, "incident_id": incident_id, "disposition": "false_positive", "note": "lab noise"},
    )
    assert res.status_code == 200
    assert res.get_json()["incident"]["disposition"] == "false_positive"


def test_llm_packets_get(app):
    client = app.test_client()
    res = client.get("/api/live/llm-packets")
    assert res.status_code == 200
    assert "running" in res.get_json()


def test_llm_test_disabled(app):
    client = app.test_client()
    res = client.post("/api/llm/test")
    assert res.status_code in (200, 503)
