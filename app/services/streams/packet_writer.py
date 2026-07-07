"""Daily JSONL persistence for live packet rows."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.services.streams.base import JsonlWriter, daily_filename

logger = logging.getLogger(__name__)


class PacketStreamWriter:
    def __init__(self, base_dir: Path, enabled: bool = True):
        self._enabled = enabled
        self._writer = JsonlWriter(base_dir) if enabled else None

    def write(self, row: dict[str, Any]) -> None:
        if not self._enabled or not self._writer:
            return
        try:
            self._writer.write_line(daily_filename("packets"), row)
        except Exception as exc:
            logger.debug("Packet stream write skip: %s", exc)
