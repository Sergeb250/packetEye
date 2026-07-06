"""Heuristic pre-filters for live AI triage (SSH brute, port scan, Hydra, FTP)."""

from __future__ import annotations

import time
from collections import defaultdict, deque


# Common brute-force / scan destination ports (CIC-IDS2017 aligned)
_BRUTE_PORTS = {
    22: ("SSH-Patator", "ssh_brute"),
    21: ("FTP-Patator", "ftp_brute"),
    23: ("Telnet brute force", "telnet_brute"),
    3389: ("RDP brute force", "rdp_brute"),
    445: ("SMB probe", "smb_scan"),
    1433: ("MSSQL brute force", "mssql_brute"),
}


class TriageHeuristics:
    """Rolling window detectors that flag packets for priority LLM analysis."""

    def __init__(self, window_sec: int = 60):
        self.window_sec = window_sec
        self._ssh_syn: dict[str, deque] = defaultdict(deque)
        self._src_ports: dict[str, deque] = defaultdict(deque)
        self._brute_hits: dict[str, deque] = defaultdict(deque)

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

        # Nmap / scan hints in Suricata or tcpdump info
        scan_keywords = ("nmap", "scan", "syn flood", "portscan", "masscan", "zmap")
        if any(k in info for k in scan_keywords):
            return {
                "attack_type": "PortScan",
                "severity": "high",
                "confidence": 0.85,
                "indicators": ["nmap_scan_signature"],
                "summary": f"Scan activity detected in packet info from {src} → {dst}",
            }

        # Hydra / medusa / patator style brute force (info or burst to auth ports)
        brute_keywords = ("hydra", "medusa", "patator", "brute", "login failed", "authentication failure")
        if dst_port in _BRUTE_PORTS and any(k in info for k in brute_keywords):
            label, indicator = _BRUTE_PORTS[dst_port]
            return {
                "attack_type": label,
                "severity": "high",
                "confidence": 0.88,
                "indicators": [indicator, "brute_tool_signature"],
                "summary": f"{label}: brute-force tool pattern from {src} toward {dst}:{dst_port}",
            }

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

        # Generic auth-port brute burst (Hydra-style without explicit signature)
        if dst_port in _BRUTE_PORTS:
            label, indicator = _BRUTE_PORTS[dst_port]
            bq = self._brute_hits[f"{src}|{dst_port}"]
            self._evict(bq, now)
            bq.append((now, dst))
            if len(bq) >= 10:
                return {
                    "attack_type": label,
                    "severity": "high",
                    "confidence": min(0.92, 0.45 + len(bq) * 0.04),
                    "indicators": [indicator, f"burst={len(bq)}"],
                    "summary": f"{label}: {len(bq)} connection attempts from {src} in {self.window_sec}s",
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
