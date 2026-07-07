"""Per-session incident JSON store for live triage."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from app.services.streams.base import atomic_write_json

logger = logging.getLogger(__name__)

MAX_INCIDENTS = 500


class IncidentTracker:
    def __init__(self, base_dir: Path):
        self._dir = Path(base_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, session_id: str) -> Path:
        return self._dir / f"{session_id}.json"

    def load(self, session_id: str) -> list[dict]:
        path = self._path(session_id)
        if not path.is_file():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return list(data) if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Incident load failed (%s): %s", session_id, exc)
            return []

    def save(self, session_id: str, rows: list[dict]) -> None:
        trimmed = rows[-MAX_INCIDENTS:]
        with self._lock:
            try:
                atomic_write_json(self._path(session_id), trimmed)
            except OSError as exc:
                logger.warning("Incident save failed (%s): %s", session_id, exc)
