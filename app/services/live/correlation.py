"""Correlate live Suricata signature alerts with ML anomalies.

When a signature hit and an ML anomaly involve the same host pair inside a
short window, that is far stronger evidence than either alone — surface it as
a single elevated finding instead of two siloed feed items.
"""

from __future__ import annotations

import time
from collections import deque


def _pair_key(src_ip: str | None, dst_ip: str | None) -> frozenset:
    return frozenset({str(src_ip or ""), str(dst_ip or "")})


class LiveCorrelator:
    """Sliding-window matcher over the two live detection feeds."""

    def __init__(self, window_seconds: int = 120):
        self.window_seconds = window_seconds
        self._suricata: deque = deque()  # (ts, key, alert_dict)
        self._ml: deque = deque()  # (ts, key, flow_dict, ml_result)
        self._correlated: set = set()  # pair keys already reported this window

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._suricata and self._suricata[0][0] < cutoff:
            _, key, _ = self._suricata.popleft()
            self._correlated.discard(key)
        while self._ml and self._ml[0][0] < cutoff:
            self._ml.popleft()

    def add_suricata(self, alert: dict, now: float | None = None) -> list[dict]:
        """Record a signature alert; return correlations with recent ML anomalies."""
        now = now or time.time()
        self._evict(now)
        key = _pair_key(alert.get("src_ip"), alert.get("dst_ip"))
        self._suricata.append((now, key, alert))

        matches = []
        if key not in self._correlated:
            for _, ml_key, flow, ml_result in self._ml:
                if ml_key == key:
                    self._correlated.add(key)
                    matches.append(self._build_match(alert, flow, ml_result))
                    break
        return matches

    def add_ml(self, flow: dict, ml_result: dict, now: float | None = None) -> list[dict]:
        """Record a flagged ML flow; return correlations with recent signature hits."""
        if not ml_result.get("flagged"):
            return []
        now = now or time.time()
        self._evict(now)
        key = _pair_key(flow.get("src_ip"), flow.get("dst_ip"))
        self._ml.append((now, key, flow, ml_result))

        matches = []
        if key not in self._correlated:
            for _, sig_key, alert in self._suricata:
                if sig_key == key:
                    self._correlated.add(key)
                    matches.append(self._build_match(alert, flow, ml_result))
                    break
        return matches

    @staticmethod
    def _build_match(suricata_alert: dict, flow: dict, ml_result: dict) -> dict:
        return {
            "signature": suricata_alert.get("signature"),
            "signature_id": suricata_alert.get("signature_id"),
            "category": suricata_alert.get("category"),
            "anomaly_score": ml_result.get("anomaly_score"),
            "ml_explanation": ml_result.get("explanation"),
            "flow_id": flow.get("id"),
            "src_ip": flow.get("src_ip") or suricata_alert.get("src_ip"),
            "dst_ip": flow.get("dst_ip") or suricata_alert.get("dst_ip"),
            "src_port": flow.get("src_port") or suricata_alert.get("src_port"),
            "dst_port": flow.get("dst_port") or suricata_alert.get("dst_port"),
            "protocol": flow.get("protocol") or suricata_alert.get("protocol"),
        }
