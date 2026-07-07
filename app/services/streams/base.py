"""Thread-safe JSONL append helpers for live streaming."""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def daily_filename(prefix: str, dt: datetime | None = None) -> str:
    day = (dt or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    return f"{prefix}_{day}.jsonl"


class JsonlWriter:
    """Append one JSON object per line with flush-after-write."""

    def __init__(self, base_dir: Path):
        self._base_dir = Path(base_dir)
        self._lock = threading.Lock()
        self._base_dir.mkdir(parents=True, exist_ok=True)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def write_line(self, filename: str, obj: dict[str, Any]) -> None:
        path = self._base_dir / filename
        line = json.dumps(obj, default=str) + "\n"
        try:
            with self._lock:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
        except OSError as exc:
            logger.warning("JSONL write failed (%s): %s", path, exc)

    def read_tail(self, filename: str, max_lines: int = 500) -> list[dict]:
        path = self._base_dir / filename
        if not path.is_file():
            return []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as exc:
            logger.warning("JSONL read failed (%s): %s", path, exc)
            return []
        out: list[dict] = []
        for line in lines[-max_lines:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


def atomic_write_json(path: Path, data: Any) -> None:
    """Write JSON atomically via temp file + replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
