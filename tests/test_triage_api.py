"""API tests for live triage endpoints."""

import pytest

from app.services.live.triage_registry import build_incident_row, upsert_incident
from app.services.streams import get_session_store


@pytest.fixture
def session_id(flask_app):
    with flask_app.app_context():
        store = get_session_store()
        assert store is not None
        record = store.create(
            eve_path="/tmp/live-test.pcap",
            interface="eth0",
            capture_source="suricata",
        )
        sid = record["id"]
        upsert_incident(
            sid,
            build_incident_row(
                session_id=sid,
                src_ip="203.0.113.1",
                dst_ip="192.168.1.1",
                dst_port=22,
                sources=["llm"],
                attack_type="SSH-Patator",
                disposition="true_positive",
                ai_status="true_positive",
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
    row = data["incidents"][0]
    assert row["attack_type"] == "SSH-Patator"
    assert row["ai_status"] == "true_positive"
    assert row["disposition"] == "true_positive"


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


def test_triage_explain_requires_ids(app):
    client = app.test_client()
    res = client.post("/api/live/triage/explain", json={})
    assert res.status_code == 400
