"""Tests for Suricata EVE path discovery."""

from pathlib import Path

from app.services.live import suricata_manager


def test_parse_eve_from_runtime_yaml(tmp_path):
    cfg = tmp_path / "suricata.yaml"
    cfg.write_text("""
default-log-dir: logs
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
""", encoding="utf-8")
    path = suricata_manager._parse_eve_from_yaml(cfg)
    assert path == tmp_path / "logs" / "eve.json"


def test_discover_eve_prefers_existing_config(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text("{}\n", encoding="utf-8")
    config = {
        "SURICATA_EVE_PATH": str(eve),
        "SURICATA_LOG_DIR": str(tmp_path),
    }
    path, source = suricata_manager.discover_eve_path(config)
    assert path == eve
    assert source == "config"
