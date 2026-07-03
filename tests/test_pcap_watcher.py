"""Tests for the tcpdump chunk watcher's closed-chunk detection + pruning."""

import time

from app.services.capture import pcap_watcher


def _make_chunk(chunk_dir, name, age_seconds, size=100):
    chunk_dir.mkdir(parents=True, exist_ok=True)
    path = chunk_dir / name
    path.write_bytes(b"x" * size)
    mtime = time.time() - age_seconds
    import os

    os.utime(path, (mtime, mtime))
    return path


def test_find_closed_chunks_skips_fresh_and_processed(tmp_path):
    chunk_dir = tmp_path / "chunks"
    _make_chunk(chunk_dir, "chunk_20260101_000000.pcap", age_seconds=60)   # closed
    _make_chunk(chunk_dir, "chunk_20260101_000500.pcap", age_seconds=2)    # still writing
    _make_chunk(chunk_dir, "chunk_20260101_001000.pcap", age_seconds=90)   # closed but processed

    closed = pcap_watcher.find_closed_chunks(
        chunk_dir, processed={"chunk_20260101_001000.pcap"}
    )
    names = [p.name for p in closed]
    assert "chunk_20260101_000000.pcap" in names
    assert "chunk_20260101_000500.pcap" not in names  # too fresh
    assert "chunk_20260101_001000.pcap" not in names  # already processed


def test_find_closed_chunks_ignores_empty(tmp_path):
    chunk_dir = tmp_path / "chunks"
    _make_chunk(chunk_dir, "chunk_empty.pcap", age_seconds=60, size=0)
    assert pcap_watcher.find_closed_chunks(chunk_dir, processed=set()) == []


def test_prune_keeps_recent(tmp_path):
    chunk_dir = tmp_path / "chunks"
    processed = set()
    for i in range(8):
        name = f"chunk_2026010{i}_000000.pcap"
        _make_chunk(chunk_dir, name, age_seconds=100 - i)
        processed.add(name)

    config = {"TCPDUMP_CHUNK_DIR": str(chunk_dir), "TCPDUMP_CHUNK_KEEP": 3}
    removed = pcap_watcher.prune_chunks(config, processed)
    remaining = list(chunk_dir.glob("chunk_*.pcap"))
    assert removed == 5
    assert len(remaining) == 3
