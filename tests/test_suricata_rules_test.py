"""Tests for draft Suricata rule validation."""

from unittest.mock import patch

from app.services.live import suricata_manager


@patch("app.services.live.suricata_manager._resolve_binary", return_value="suricata")
def test_test_rules_draft_rejects_empty(mock_bin, tmp_path):
    cfg = {
        "SURICATA_BIN": "suricata",
        "SURICATA_LOG_DIR": str(tmp_path / "log"),
        "SURICATA_INTERFACE": "eth0",
        "SURICATA_CUSTOM_RULES_PATH": str(tmp_path / "custom.rules"),
    }
    result = suricata_manager.test_rules_draft(cfg, "", "eth0")
    assert result["ok"] is False
    assert "No rules" in result["error"]


@patch("app.services.live.suricata_manager._resolve_binary", return_value=None)
def test_test_rules_draft_no_suricata(mock_bin, tmp_path):
    cfg = {"SURICATA_LOG_DIR": str(tmp_path)}
    result = suricata_manager.test_rules_draft(cfg, 'alert tcp any any -> any any (msg:"x"; sid:1000999; rev:1;)', "eth0")
    assert result["ok"] is False
    assert "not installed" in result["error"]
