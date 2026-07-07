"""Tests for JSON streaming writers."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from app.services.streams.alert_writer import AlertStreamWriter
from app.services.streams.base import JsonlWriter, atomic_write_json
from app.services.streams.incident_tracker import IncidentTracker
from app.services.streams.session_store import LiveSessionStore


def test_jsonl_writer_append(tmp_path):
    writer = JsonlWriter(tmp_path / "packets")
    writer.write_line("test.jsonl", {"id": 1, "value": "a"})
    writer.write_line("test.jsonl", {"id": 2, "value": "b"})
    rows = writer.read_tail("test.jsonl")
    assert len(rows) == 2
    assert rows[0]["id"] == 1


def test_jsonl_writer_concurrent(tmp_path):
    writer = JsonlWriter(tmp_path / "packets")

    def _write(n: int):
        for i in range(20):
            writer.write_line("concurrent.jsonl", {"thread": n, "i": i})

    threads = [threading.Thread(target=_write, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rows = writer.read_tail("concurrent.jsonl", max_lines=200)
    assert len(rows) == 100


def test_session_store_atomic_update(tmp_path):
    store = LiveSessionStore(tmp_path / "sessions")
    record = store.create(interface="eth0", capture_source="scapy")
    sid = record["id"]
    updated = store.update(sid, {"total_flows": 42, "status": "analyzing"})
    assert updated["total_flows"] == 42
    loaded = store.get(sid)
    assert loaded["total_flows"] == 42
    summary_patch = store.update(sid, {"summary_json": {"eve_path": "/new/eve.json"}})
    assert summary_patch["summary_json"]["eve_path"] == "/new/eve.json"
    assert summary_patch["summary_json"]["capture_source"] == "scapy"


def test_session_store_find_running(tmp_path):
    store = LiveSessionStore(tmp_path / "sessions")
    a = store.create(capture_source="suricata")
    store.update(a["id"], {"status": "complete"})
    b = store.create(capture_source="suricata")
    store.update(b["id"], {"status": "analyzing"})
    running = store.find_running()
    assert running is not None
    assert running["id"] == b["id"]


def test_alert_writer_deque_and_file(tmp_path):
    writer = AlertStreamWriter(tmp_path / "alerts")
    alert = {
        "id": "alert-1",
        "session_id": "sess-a",
        "timestamp": 100.0,
        "severity": "high",
        "type": "ml",
    }
    writer.write(alert)
    recent = writer.get_since("sess-a", since_ts=0)
    assert len(recent) == 1
    assert recent[0]["finding_id"] == "alert-1"

    path = tmp_path / "alerts" / "alerts_sess-a.jsonl"
    assert path.is_file()
    line = path.read_text(encoding="utf-8").strip()
    assert json.loads(line)["id"] == "alert-1"


def test_alert_writer_update(tmp_path):
    writer = AlertStreamWriter(tmp_path / "alerts")
    writer.write(
        {
            "id": "a2",
            "session_id": "sess-b",
            "timestamp": 50.0,
            "severity": "medium",
            "type": "suricata",
        }
    )
    updated = writer.update("sess-b", "a2", {"enhanced": {"summary": "test"}, "severity": "high"})
    assert updated["severity"] == "high"
    assert updated["enhanced"]["summary"] == "test"
    recent = writer.get_since("sess-b", since_ts=0)
    assert recent[0]["severity"] == "high"


def test_incident_tracker_save_load(tmp_path):
    tracker = IncidentTracker(tmp_path / "incidents")
    rows = [{"id": "1", "attack_type": "PortScan"}, {"id": "2", "attack_type": "Bot"}]
    tracker.save("sess-x", rows)
    loaded = tracker.load("sess-x")
    assert len(loaded) == 2
    path = tmp_path / "incidents" / "sess-x.json"
    assert path.is_file()
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk[0]["attack_type"] == "PortScan"


def test_atomic_write_json(tmp_path):
    path = tmp_path / "nested" / "data.json"
    atomic_write_json(path, {"ok": True})
    assert json.loads(path.read_text(encoding="utf-8"))["ok"] is True
