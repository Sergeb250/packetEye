"""Tests for unified capture + ML session wiring."""

from pathlib import Path

from app.services.capture import orchestrator
from app.services.capture import ml_capture


def _config(tmp_path, **overrides):
    model = tmp_path / "model.joblib"
    model.write_bytes(b"x")
    cfg = {
        "CAPTURE_MODE": "tcpdump",
        "CAPTURE_INTERFACE": "eth0",
        "CAPTURE_STATE_DIR": str(tmp_path / "capture"),
        "ML_MODEL_PATH": str(model),
        "LIVE_ML_TCPDUMP_ENABLED": True,
        "SURICATA_EVE_PATH": str(tmp_path / "eve.json"),
    }
    cfg.update(overrides)
    return cfg


def test_ml_session_id_roundtrip(tmp_path):
    cfg = _config(tmp_path)
    state_dir = Path(cfg["CAPTURE_STATE_DIR"])
    state_dir.mkdir(parents=True)
    (state_dir / "capture_state.json").write_text(
        '{"mode": "tcpdump", "pid": 1, "interface": "eth0"}',
        encoding="utf-8",
    )
    orchestrator.set_ml_session_id(cfg, "abc-123")
    assert orchestrator.get_ml_session_id(cfg) == "abc-123"
    orchestrator.set_ml_session_id(cfg, None)
    assert orchestrator.get_ml_session_id(cfg) is None


def test_attach_ml_model_missing(tmp_path):
    cfg = _config(tmp_path)
    Path(cfg["ML_MODEL_PATH"]).unlink()
    result = ml_capture.attach_ml_to_capture(cfg, "tcpdump", "eth0")
    assert result["status"] == "model_missing"
    assert result["session_id"] is None


def test_attach_ml_tcpdump_disabled(tmp_path):
    cfg = _config(tmp_path, LIVE_ML_TCPDUMP_ENABLED=False)
    result = ml_capture.attach_ml_to_capture(cfg, "tcpdump", "eth0")
    assert result["status"] == "disabled"


def test_attach_ml_reuses_running_session(tmp_path, monkeypatch):
    cfg = _config(tmp_path)
    state_dir = Path(cfg["CAPTURE_STATE_DIR"])
    state_dir.mkdir(parents=True)
    (state_dir / "capture_state.json").write_text(
        '{"mode": "tcpdump", "pid": 1, "interface": "eth0", "ml_session_id": "sess-1"}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ml_capture,
        "monitor_status",
        lambda sid: {"running": True, "session_id": sid},
    )
    result = ml_capture.attach_ml_to_capture(cfg, "tcpdump", "eth0")
    assert result["status"] == "already_running"
    assert result["session_id"] == "sess-1"
