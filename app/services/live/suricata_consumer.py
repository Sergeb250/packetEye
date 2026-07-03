"""Tail Suricata EVE JSON and emit closed flow events."""

import json
import logging
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

from app.services.live.eve_parser import iter_eve_events_from_text, normalize_eve_event
from app.services.live.suricata_mapper import eve_alert_to_alert_dict, eve_flow_to_flow_dict

logger = logging.getLogger(__name__)


class PortEntropyTracker:
    """Rolling per-src port entropy for live flows."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self._history: dict[str, deque] = defaultdict(deque)

    def record(self, src_ip: str, dst_port: int, ts: float | None = None):
        now = ts or time.time()
        hist = self._history[src_ip]
        hist.append((now, dst_port))
        cutoff = now - self.window_seconds
        while hist and hist[0][0] < cutoff:
            hist.popleft()

    def entropy(self, src_ip: str) -> float:
        hist = self._history.get(src_ip)
        if not hist:
            return 0.0
        counts: dict[int, int] = defaultdict(int)
        for _, port in hist:
            counts[port] += 1
        total = len(hist)
        import math

        return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


class SuricataConsumer:
    """Incrementally read Suricata EVE JSON flow events."""

    def __init__(self, eve_path: str | Path, entropy_window: int = 300):
        self.eve_path = Path(eve_path)
        self._offset = 0
        self._inode = None
        self.entropy_tracker = PortEntropyTracker(entropy_window)

    def _reset_if_rotated(self):
        if not self.eve_path.exists():
            return
        stat = self.eve_path.stat()
        inode = (stat.st_ino, stat.st_size)
        if self._inode and inode[0] != self._inode[0] and stat.st_size < self._offset:
            logger.info("EVE log rotated, resetting offset")
            self._offset = 0
        self._inode = inode

    def poll(self, max_lines: int = 500) -> list[dict]:
        """Backwards-compatible flow-only poll."""
        return self.poll_events(max_lines)["flows"]

    def poll_events(self, max_lines: int = 500) -> dict[str, list[dict]]:
        """Read new EVE events; returns {"flows": [...], "alerts": [...]}.

        Flows feed the ML scorer; alerts are Suricata signature hits that get
        surfaced directly in the live feed.
        """
        result: dict[str, list[dict]] = {"flows": [], "alerts": []}
        if not self.eve_path.exists():
            return result

        self._reset_if_rotated()

        with open(self.eve_path, encoding="utf-8", errors="replace") as f:
            f.seek(self._offset)
            if self._offset == 0:
                prefix = f.read(4096)
                if prefix.lstrip().startswith("["):
                    f.seek(0)
                    chunk = f.read()
                    self._offset = f.tell()
                    for event in iter_eve_events_from_text(chunk):
                        self._collect_event(event, result)
                    return result
                f.seek(self._offset)

            for _ in range(max_lines):
                line = f.readline()
                if not line:
                    break
                self._offset = f.tell()
                line = line.strip()
                if not line:
                    continue
                try:
                    event = normalize_eve_event(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if not event:
                    continue
                self._collect_event(event, result)

        return result

    def _collect_event(self, event: dict, result: dict[str, list[dict]]) -> None:
        etype = event.get("event_type")
        if etype == "flow":
            flow_dict = self._flow_from_event(event)
            if flow_dict:
                result["flows"].append(flow_dict)
        elif etype == "alert":
            alert_dict = eve_alert_to_alert_dict(event)
            if alert_dict:
                result["alerts"].append(alert_dict)

    def _flow_from_event(self, event: dict) -> dict | None:
        if event.get("event_type") != "flow":
            return None
        flow_id = str(uuid.uuid4())
        flow_dict = eve_flow_to_flow_dict(event, flow_id=flow_id)
        if not flow_dict or not flow_dict.get("src_ip"):
            return None
        src = flow_dict["src_ip"]
        dst_port = flow_dict["dst_port"]
        self.entropy_tracker.record(src, dst_port)
        flow_dict["dst_port_entropy"] = self.entropy_tracker.entropy(src)
        return flow_dict
