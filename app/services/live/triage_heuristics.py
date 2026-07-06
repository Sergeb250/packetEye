"""Heuristic pre-filters for live AI triage (SSH brute, port scan)."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class TriageHeuristics:
    """Rolling window detectors that flag packets for priority LLM analysis."""

    def __init__(self, window_sec: int = 60):
        self.window_sec = window_sec
        self._ssh_syn: dict[str, deque] = defaultdict(deque)
        self._src_ports: dict[str, deque] = defaultdict(deque)

    def _evict(self, dq: deque, now: float) -> None:
        cutoff = now - self.window_sec
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def analyze(self, packet: dict) -> dict | None:
        """Return heuristic hit dict or None."""
        now = float(packet.get("timestamp") or time.time())
        src = str(packet.get("src_ip") or "")
        dst = str(packet.get("dst_ip") or "")
        dst_port = int(packet.get("dst_port") or 0)
        proto = str(packet.get("protocol") or "TCP").upper()
        info = str(packet.get("info") or "").lower()

        if not src or not dst:
            return None

        # SSH brute: many connections/events toward port 22
        if dst_port == 22 or "ssh" in info or ":22" in info:
            dq = self._ssh_syn[src]
            self._evict(dq, now)
            dq.append((now, dst))
            if len(dq) >= 8:
                return {
                    "attack_type": "SSH-Patator",
                    "severity": "high",
                    "confidence": min(0.95, 0.5 + len(dq) * 0.04),
                    "indicators": ["ssh_syn_burst", f"count={len(dq)}"],
                    "summary": f"SSH brute-force pattern: {len(dq)} events to port 22 from {src} in {self.window_sec}s",
                }

        # Port scan: high destination port diversity from one source
        if proto == "TCP" and dst_port > 0:
            pq = self._src_ports[src]
            self._evict(pq, now)
            pq.append((now, dst_port))
            ports = {p for _, p in pq}
            if len(ports) >= 15:
                return {
                    "attack_type": "PortScan",
                    "severity": "medium",
                    "confidence": min(0.9, 0.4 + len(ports) * 0.03),
                    "indicators": ["port_scan_entropy", f"unique_ports={len(ports)}"],
                    "summary": f"Port scan pattern: {len(ports)} unique ports from {src} in {self.window_sec}s",
                }

        return None
