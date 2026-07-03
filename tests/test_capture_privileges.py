"""Tests for capture privilege / writable directory helpers."""

from pathlib import Path

from app.services.capture import privileges


def test_ensure_writable_dir(tmp_path):
    target = tmp_path / "logs" / "suricata"
    ok, err = privileges.ensure_writable_dir(target)
    assert ok is True
    assert err is None
    assert target.is_dir()


def test_default_tcpdump_chunk_dir_linux_non_root(monkeypatch, tmp_path):
    monkeypatch.setattr(privileges.sys, "platform", "linux")
    monkeypatch.setattr(privileges, "running_as_root", lambda: False)
    monkeypatch.setattr(privileges.os, "getuid", lambda: 1000)
    path = privileges.default_tcpdump_chunk_dir(tmp_path)
    assert str(path) == "/tmp/packeteye/chunks-1000"


def test_default_tcpdump_chunk_dir_linux_root(monkeypatch, tmp_path):
    monkeypatch.setattr(privileges.sys, "platform", "linux")
    monkeypatch.setattr(privileges, "running_as_root", lambda: True)
    path = privileges.default_tcpdump_chunk_dir(tmp_path)
    assert path == privileges._LINUX_ROOT_CHUNKS


def test_reclaim_unwritable_chunks(tmp_path, monkeypatch):
    chunk_dir = tmp_path / "chunks"
    chunk_dir.mkdir()
    blocked = chunk_dir / "chunk_20260101_120000.pcap"
    blocked.write_bytes(b"pcap")
    monkeypatch.setattr(privileges.os, "access", lambda _p, _m: False)
    monkeypatch.setattr(privileges, "running_as_root", lambda: True)
    removed = privileges.reclaim_unwritable_chunks(chunk_dir)
    assert "chunk_20260101_120000.pcap" in removed
    assert not blocked.exists()


def test_prepare_tcpdump_chunk_dir(tmp_path):
    chunk_dir = tmp_path / "chunks"
    ok, err, _removed = privileges.prepare_tcpdump_chunk_dir(chunk_dir)
    assert ok is True
    assert err is None
    assert chunk_dir.is_dir()


def test_tcpdump_failure_hint_apparmor(tmp_path):
    hint = privileges.tcpdump_failure_hint(
        "tcpdump: /home/kali/chunks/chunk_x.pcap: Permission denied",
        tmp_path / "chunks",
    )
    assert hint is not None
    assert "TCPDUMP_CHUNK_DIR" in hint or "AppArmor" in hint
