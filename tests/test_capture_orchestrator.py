"""Tests for the capture orchestrator (no real Suricata/tcpdump needed)."""

from pathlib import Path

from app.services.capture import orchestrator


def _config(tmp_path, **overrides):
    cfg = {
        "CAPTURE_MODE": "suricata",
        "CAPTURE_INTERFACE": "eth0",
        "CAPTURE_STATE_DIR": str(tmp_path / "capture"),
        "TCPDUMP_BIN": str(tmp_path / "no-tcpdump"),
        "TCPDUMP_CHUNK_DIR": str(tmp_path / "chunks"),
        "TCPDUMP_CHUNK_SECONDS": 300,
        "TCPDUMP_CHUNK_KEEP": 5,
        "SURICATA_BIN": str(tmp_path / "no-suricata"),
        "SURICATA_EVE_PATH": str(tmp_path / "eve.json"),
        "SURICATA_LOG_DIR": str(tmp_path / "slog"),
        "SURICATA_CUSTOM_RULES_PATH": str(tmp_path / "custom.rules"),
    }
    cfg.update(overrides)
    return cfg


def test_status_when_nothing_running(tmp_path):
    status = orchestrator.capture_status(_config(tmp_path))
    assert status["running"] is False
    assert status["mode"] is None
    assert status["tcpdump"]["installed"] is False


def test_start_rejects_unknown_mode(tmp_path):
    result = orchestrator.start_capture(_config(tmp_path), mode="wireshark", interface="eth0")
    assert result["ok"] is False
    assert "mode" in result["error"].lower()


def test_start_requires_interface(tmp_path):
    result = orchestrator.start_capture(_config(tmp_path, CAPTURE_INTERFACE=""), mode="tcpdump", interface="")
    assert result["ok"] is False
    assert "interface" in result["error"].lower()


def test_tcpdump_missing_binary(tmp_path):
    result = orchestrator.start_capture(_config(tmp_path), mode="tcpdump", interface="eth0")
    assert result["ok"] is False
    assert "tcpdump" in result["error"].lower()


def test_stop_when_idle(tmp_path):
    result = orchestrator.stop_capture(_config(tmp_path))
    assert result["ok"] is False


def test_stale_state_not_reported_as_running(tmp_path, monkeypatch):
    cfg = _config(tmp_path)
    state_dir = Path(cfg["CAPTURE_STATE_DIR"])
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "capture_state.json").write_text(
        '{"mode": "suricata", "pid": 999999, "interface": "eth0"}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        orchestrator.suricata_manager,
        "get_status",
        lambda _cfg: {
            "installed": True,
            "running": True,
            "managed": False,
            "managed_pid": None,
            "version": "test",
            "eve": {"path": str(tmp_path / "eve.json"), "exists": False},
        },
    )
    status = orchestrator.capture_status(cfg)
    assert status["running"] is False
    assert status["external_suricata"] is True
    assert status["stoppable"] is False
    assert not (state_dir / "capture_state.json").is_file()
