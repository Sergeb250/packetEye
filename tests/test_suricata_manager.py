"""Tests for Suricata process/rules management (no real Suricata required)."""

from app.services.live import suricata_manager


def _config(tmp_path, **overrides):
    cfg = {
        "SURICATA_BIN": str(tmp_path / "definitely-not-suricata.exe"),
        "SURICATA_CONFIG_PATH": "",
        "SURICATA_INTERFACE": "",
        "SURICATA_LOG_DIR": str(tmp_path / "logs"),
        "SURICATA_EVE_PATH": str(tmp_path / "eve.json"),
        "SURICATA_CUSTOM_RULES_PATH": str(tmp_path / "custom.rules"),
    }
    cfg.update(overrides)
    return cfg


def test_status_reports_missing_binary(tmp_path):
    status = suricata_manager.get_status(_config(tmp_path))
    assert status["installed"] is False
    assert status["managed"] is False
    assert status["eve"]["exists"] is False


def test_start_fails_without_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(suricata_manager, "_find_running_pids", lambda: [])
    result = suricata_manager.start_suricata(_config(tmp_path), interface="eth0")
    assert result["ok"] is False
    assert "not found" in result["error"]


def test_start_requires_interface(tmp_path, monkeypatch):
    binary = tmp_path / "suricata"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr(suricata_manager, "_find_running_pids", lambda: [])
    result = suricata_manager.start_suricata(
        _config(tmp_path, SURICATA_BIN=str(binary)), interface=""
    )
    assert result["ok"] is False
    assert "interface" in result["error"].lower()


def test_stop_without_running_process(monkeypatch):
    monkeypatch.setattr(suricata_manager, "_find_running_pids", lambda: [])
    suricata_manager._managed["process"] = None
    result = suricata_manager.stop_suricata()
    assert result["ok"] is False


def test_rules_roundtrip(tmp_path):
    cfg = _config(tmp_path)

    empty = suricata_manager.read_rules(cfg)
    assert empty["ok"] is True
    assert empty["content"] == ""
    assert empty["exists"] is False

    rule = 'alert tcp any any -> any 22 (msg:"test"; sid:1000001; rev:1;)\n'
    saved = suricata_manager.write_rules(cfg, rule)
    assert saved["ok"] is True
    assert saved["size_bytes"] == len(rule.encode("utf-8"))

    loaded = suricata_manager.read_rules(cfg)
    assert loaded["ok"] is True
    assert loaded["content"] == rule
    assert loaded["exists"] is True


def test_rules_reject_binary_and_oversize(tmp_path):
    cfg = _config(tmp_path)
    assert suricata_manager.write_rules(cfg, "bad\x00rule")["ok"] is False
    huge = "a" * (suricata_manager.MAX_RULES_BYTES + 1)
    assert suricata_manager.write_rules(cfg, huge)["ok"] is False


def test_rules_require_configured_path(tmp_path):
    cfg = _config(tmp_path, SURICATA_CUSTOM_RULES_PATH="")
    assert suricata_manager.read_rules(cfg)["ok"] is False
    assert suricata_manager.write_rules(cfg, "x")["ok"] is False


def test_parse_suricata_output_severity():
    text = "Info: loading rules\nError: bad rule\nWarning: deprecated option\nFATAL: failed"
    rows = suricata_manager.parse_suricata_output(text)
    assert len(rows) == 4
    assert rows[0]["severity"] == "info"
    assert rows[1]["severity"] in ("error", "critical")
    assert rows[2]["severity"] == "warning"
    assert rows[3]["severity"] == "critical"


def test_start_blocks_loopback(tmp_path, monkeypatch):
    binary = tmp_path / "suricata"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr(suricata_manager, "_find_running_pids", lambda: [])
    result = suricata_manager.start_suricata(
        _config(tmp_path, SURICATA_BIN=str(binary)), interface="lo"
    )
    assert result["ok"] is False
    assert "lo" in result["error"].lower()
    assert result.get("diagnostics")


def test_build_runtime_config_writes_yaml(tmp_path):
    cfg = _config(tmp_path)
    path, source = suricata_manager._build_runtime_config(cfg, "eth0")
    assert source == "runtime"
    assert Path(path).is_file()
    text = Path(path).read_text(encoding="utf-8")
    assert "interface: eth0" in text
    assert "eve.json" in text
    assert "default-log-dir" in text


def test_resolve_run_config_falls_back_to_runtime(tmp_path, monkeypatch):
    cfg = _config(tmp_path)
    monkeypatch.setattr(suricata_manager, "_resolve_config_path", lambda _c: (None, "missing"))
    path, source = suricata_manager._resolve_run_config(cfg, "eth0")
    assert source == "runtime"
    assert Path(path).is_file()


def test_preflight_blocks_loopback(tmp_path):
    cfg = _config(tmp_path)
    result = suricata_manager.run_preflight(cfg, interface="lo")
    assert result["ok"] is False
    assert "lo" in (result.get("error") or "").lower()


def test_get_diagnostics_includes_rows(tmp_path):
    suricata_manager._last_diagnostics.clear()
    suricata_manager._last_diagnostics.extend(
        suricata_manager.parse_suricata_output("Error: test failure")
    )
    diag = suricata_manager.get_diagnostics(_config(tmp_path))
    assert diag["rows"]
    assert diag["rows"][-1]["message"] == "Error: test failure"
