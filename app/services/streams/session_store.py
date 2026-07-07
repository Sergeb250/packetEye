"""Live session metadata on disk (replaces Analysis ORM for source=live)."""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.streams.base import atomic_write_json

logger = logging.getLogger(__name__)

_RUNNING_STATUSES = frozenset({"analyzing", "running"})


class LiveSessionStore:
    def __init__(self, base_dir: Path):
        self._dir = Path(base_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, session_id: str) -> Path:
        return self._dir / f"{session_id}.json"

    def create(
        self,
        *,
        eve_path: str | None = None,
        interface: str | None = None,
        capture_source: str = "suricata",
        analysis_name: str | None = None,
    ) -> dict[str, Any]:
        session_id = str(uuid.uuid4())
        label = interface or ("scapy" if capture_source == "scapy" else "suricata")
        now = datetime.now(timezone.utc)
        record = {
            "id": session_id,
            "created_at": now.isoformat(),
            "status": "analyzing",
            "source": "live",
            "filename": f"live-{label}",
            "file_path": str(eve_path) if capture_source != "scapy" else f"scapy://{interface or 'eth0'}",
            "analysis_name": analysis_name
            or f"Live NIDS {now.strftime('%Y-%m-%d %H:%M')}",
            "total_flows": 0,
            "total_findings": 0,
            "progress_pct": 10,
            "summary_json": {
                "interface": interface,
                "eve_path": eve_path or "",
                "live": True,
                "capture_source": capture_source,
                "capture_mode": capture_source if capture_source == "scapy" else "suricata",
            },
        }
        self._write(session_id, record)
        return record

    def get(self, session_id: str) -> dict[str, Any] | None:
        path = self._path(session_id)
        if not path.is_file():
            return None
        try:
            import json

            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Session read failed (%s): %s", session_id, exc)
            return None

    def update(self, session_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            record = self.get(session_id)
            if not record:
                return None
            if "summary_json" in patch and isinstance(patch["summary_json"], dict):
                merged = dict(record.get("summary_json") or {})
                merged.update(patch["summary_json"])
                patch = {**patch, "summary_json": merged}
            record.update(patch)
            self._write_unlocked(session_id, record)
            return record

    def list_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        files = sorted(self._dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        out: list[dict[str, Any]] = []
        for path in files[:limit]:
            if path.name.endswith(".tmp"):
                continue
            session_id = path.stem
            row = self.get(session_id)
            if row:
                out.append(row)
        return out

    def find_running(self) -> dict[str, Any] | None:
        for row in self.list_recent(limit=50):
            if row.get("status") in _RUNNING_STATUSES:
                return row
        return None

    def _write(self, session_id: str, record: dict[str, Any]) -> None:
        with self._lock:
            self._write_unlocked(session_id, record)

    def _write_unlocked(self, session_id: str, record: dict[str, Any]) -> None:
        try:
            atomic_write_json(self._path(session_id), record)
        except OSError as exc:
            logger.warning("Session write failed (%s): %s", session_id, exc)
