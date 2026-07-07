"""Session-scoped alert JSONL + in-memory recent deque."""

from __future__ import annotations

import logging
import threading
from collections import deque
from pathlib import Path
from typing import Any

from app.services.streams.base import JsonlWriter

logger = logging.getLogger(__name__)

MAX_RECENT = 200


class AlertStreamWriter:
    def __init__(self, base_dir: Path, enabled: bool = True):
        self._enabled = enabled
        self._writer = JsonlWriter(base_dir) if enabled else None
        self._recent: dict[str, deque] = {}
        self._lock = threading.Lock()

    def _filename(self, session_id: str) -> str:
        return f"alerts_{session_id}.jsonl"

    def _deque(self, session_id: str) -> deque:
        with self._lock:
            if session_id not in self._recent:
                self._recent[session_id] = deque(maxlen=MAX_RECENT)
            return self._recent[session_id]

    def _hydrate_from_file(self, session_id: str) -> None:
        if not self._writer:
            return
        dq = self._deque(session_id)
        if dq:
            return
        for row in self._writer.read_tail(self._filename(session_id), max_lines=MAX_RECENT):
            dq.append(row)

    def write(self, alert: dict[str, Any]) -> None:
        session_id = str(alert.get("session_id") or "")
        if not session_id:
            return
        alert = dict(alert)
        alert.setdefault("finding_id", alert.get("id"))
        self._deque(session_id).append(alert)
        if self._enabled and self._writer:
            try:
                self._writer.write_line(self._filename(session_id), alert)
            except Exception as exc:
                logger.debug("Alert stream write skip: %s", exc)

    def update(self, session_id: str, alert_id: str, patch: dict[str, Any]) -> dict | None:
        self._hydrate_from_file(session_id)
        dq = self._deque(session_id)
        updated = None
        for i, row in enumerate(dq):
            if row.get("id") == alert_id:
                merged = dict(row)
                merged.update(patch)
                dq[i] = merged
                updated = merged
                break
        if updated and self._enabled and self._writer:
            record = dict(updated)
            record["_update"] = True
            try:
                self._writer.write_line(self._filename(session_id), record)
            except Exception as exc:
                logger.debug("Alert stream update skip: %s", exc)
        return updated

    def get_since(self, session_id: str, since_ts: float = 0) -> list[dict]:
        self._hydrate_from_file(session_id)
        dq = self._deque(session_id)
        return [a for a in dq if float(a.get("timestamp") or 0) > since_ts]

    @staticmethod
    def get_alerts(session_id: str, since_ts: float = 0) -> list[dict]:
        from app.services.streams import get_alert_writer

        writer = get_alert_writer()
        if writer:
            return writer.get_since(session_id, since_ts)
        return []
