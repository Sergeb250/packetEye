"""Watch the tcpdump chunk directory and auto-analyze closed PCAP chunks.

tcpdump keeps capturing while this watcher feeds finished chunks through the
existing PCAP pipeline (parse → rules + ML → report). With
ENRICHMENT_MODE=on_investigate the pipeline skips bulk OSINT, so chunks are
analyzed in seconds and analysts investigate only the alerts that matter.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# A chunk is "closed" once tcpdump stopped writing to it for this long.
CHUNK_STABLE_SECONDS = 15
POLL_INTERVAL_SECONDS = 10

_watcher: dict = {"thread": None, "stop": None, "processed": 0, "last_chunk": None}


def _chunk_dir(config: dict) -> Path:
    state_path = Path(str(config.get("CAPTURE_STATE_DIR") or "data/capture")) / "capture_state.json"
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if state.get("chunk_dir"):
                return Path(str(state["chunk_dir"]))
        except (json.JSONDecodeError, OSError):
            pass
    from app.services.capture.privileges import resolve_tcpdump_chunk_dir

    return resolve_tcpdump_chunk_dir(config)


def _processed_path(config: dict) -> Path:
    return Path(str(config.get("CAPTURE_STATE_DIR") or "data/capture")) / "processed_chunks.json"


def _load_processed(config: dict) -> set[str]:
    path = _processed_path(config)
    if not path.is_file():
        return set()
    try:
        return set(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError):
        return set()


def _save_processed(config: dict, processed: set[str]) -> None:
    path = _processed_path(config)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sorted(processed)[-500:]), encoding="utf-8")
    except OSError as exc:
        logger.debug("Could not persist processed chunk list: %s", exc)


def find_closed_chunks(chunk_dir: Path, processed: set[str], now: float | None = None) -> list[Path]:
    """Chunks tcpdump has finished writing (mtime stable), oldest first."""
    if not chunk_dir.is_dir():
        return []
    now = now or time.time()
    closed = []
    for path in sorted(chunk_dir.glob("chunk_*.pcap"), key=lambda p: p.stat().st_mtime):
        if path.name in processed:
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        if stat.st_size > 0 and (now - stat.st_mtime) >= CHUNK_STABLE_SECONDS:
            closed.append(path)
    return closed


def prune_chunks(config: dict, processed: set[str]) -> int:
    """Delete oldest processed chunks beyond TCPDUMP_CHUNK_KEEP."""
    keep = max(1, int(config.get("TCPDUMP_CHUNK_KEEP", 10)))
    chunk_dir = _chunk_dir(config)
    if not chunk_dir.is_dir():
        return 0
    chunks = sorted(chunk_dir.glob("chunk_*.pcap"), key=lambda p: p.stat().st_mtime)
    removed = 0
    for path in chunks[:-keep]:
        if path.name not in processed:
            continue
        try:
            path.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def _analyze_chunk(app, chunk: Path) -> str | None:
    from app.extensions import db
    from app.models.analysis import Analysis
    from app.services.analysis_runner import kickoff_analysis

    analysis = Analysis(
        id=str(uuid.uuid4()),
        filename=chunk.name,
        file_path=str(chunk),
        analysis_name=f"tcpdump chunk {datetime.now(timezone.utc).strftime('%H:%M')}",
        source="live_pcap",
        status="queued",
        progress_pct=0,
        summary_json={"live": True, "capture_mode": "tcpdump", "chunk": chunk.name},
    )
    db.session.add(analysis)
    db.session.commit()
    kickoff_analysis(app, analysis.id)
    logger.info("Queued analysis %s for chunk %s", analysis.id, chunk.name)
    return analysis.id


def _run_loop(app, stop_event: threading.Event):
    with app.app_context():
        config = dict(app.config)
        processed = _load_processed(config)
        logger.info("PCAP chunk watcher started (%s)", _chunk_dir(config))
        while not stop_event.is_set():
            try:
                for chunk in find_closed_chunks(_chunk_dir(config), processed):
                    try:
                        _analyze_chunk(app, chunk)
                        processed.add(chunk.name)
                        _watcher["processed"] += 1
                        _watcher["last_chunk"] = chunk.name
                    except Exception:
                        logger.exception("Chunk analysis failed for %s", chunk)
                _save_processed(config, processed)
                prune_chunks(config, processed)
            except Exception:
                logger.exception("Chunk watcher iteration failed")
            stop_event.wait(POLL_INTERVAL_SECONDS)
        logger.info("PCAP chunk watcher stopped")


def start_watcher(app) -> bool:
    thread = _watcher.get("thread")
    if thread is not None and thread.is_alive():
        return False
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_run_loop, args=(app, stop_event), name="pcap-chunk-watcher", daemon=True
    )
    _watcher.update({"thread": thread, "stop": stop_event})
    thread.start()
    return True


def stop_watcher() -> bool:
    stop_event = _watcher.get("stop")
    thread = _watcher.get("thread")
    if not stop_event or thread is None:
        return False
    stop_event.set()
    thread.join(timeout=15)
    _watcher.update({"thread": None, "stop": None})
    return True


def watcher_status() -> dict:
    thread = _watcher.get("thread")
    return {
        "running": thread is not None and thread.is_alive(),
        "chunks_processed": _watcher.get("processed", 0),
        "last_chunk": _watcher.get("last_chunk"),
    }
