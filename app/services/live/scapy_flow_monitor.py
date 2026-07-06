"""Aggregate Scapy live packets into flow dicts for ML scoring."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from app.services.live import packet_feed
from app.services.net_utils import is_external_ip

logger = logging.getLogger(__name__)


def _flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> str:
    return f"{proto}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"


class ScapyFlowMonitor:
    """Poll live packet feed and emit completed flows for ML."""

    def __init__(self, idle_seconds: float = 5.0):
        self.idle_seconds = idle_seconds
        self._since_id = 0
        self._active: dict[str, dict] = {}

    def poll_events(self) -> dict:
        packets = packet_feed.poll_packets(self._since_id)
        now = time.time()
        for pkt in packets:
            self._since_id = max(self._since_id, pkt.get("id") or 0)
            if pkt.get("source") != "scapy" or pkt.get("event_type") != "packet":
                continue
            self._ingest_packet(pkt, now)

        flows = self._flush_idle(now)
        return {"flows": flows, "alerts": []}

    def _ingest_packet(self, pkt: dict, now: float) -> None:
        src_ip = pkt.get("src_ip") or ""
        dst_ip = pkt.get("dst_ip") or ""
        if not src_ip or not dst_ip:
            return
        proto = str(pkt.get("protocol") or "TCP").upper()
        src_port = int(pkt.get("src_port") or 0)
        dst_port = int(pkt.get("dst_port") or 0)
        key = _flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        length = int(pkt.get("length") or 0)
        ts = float(pkt.get("timestamp") or now)

        if key not in self._active:
            self._active[key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "start_time": datetime.fromtimestamp(ts, tz=timezone.utc),
                "end_time": datetime.fromtimestamp(ts, tz=timezone.utc),
                "bytes_sent": 0,
                "bytes_recv": 0,
                "packets_sent": 0,
                "packets_recv": 0,
                "iat_samples": [],
                "last_ts": ts,
                "is_external_dst": is_external_ip(dst_ip),
            }
        flow = self._active[key]
        if ts > flow["last_ts"]:
            flow["iat_samples"].append(ts - flow["last_ts"])
        flow["last_ts"] = ts
        flow["end_time"] = datetime.fromtimestamp(ts, tz=timezone.utc)
        flow["bytes_sent"] += length
        flow["packets_sent"] += 1
        flow["bytes_recv"] = flow["bytes_sent"]
        flow["packets_recv"] = flow["packets_sent"]

    def _flush_idle(self, now: float) -> list[dict]:
        ready = []
        stale = []
        for key, flow in self._active.items():
            if now - flow["last_ts"] >= self.idle_seconds:
                stale.append(key)
                ready.append(self._to_flow_dict(flow))
        for key in stale:
            del self._active[key]
        return ready

    def _to_flow_dict(self, flow: dict) -> dict:
        iats = flow.get("iat_samples") or []
        start = flow.get("start_time")
        end = flow.get("end_time")
        duration_ms = 0
        if start and end:
            duration_ms = max(0, int((end - start).total_seconds() * 1000))
        iat_mean = sum(iats) / len(iats) if iats else 0.0
        return {
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
            "start_time": start,
            "end_time": end,
            "duration_ms": duration_ms,
            "bytes_sent": flow["bytes_sent"],
            "bytes_recv": flow["bytes_recv"],
            "packets_sent": flow["packets_sent"],
            "packets_recv": flow["packets_recv"],
            "iat_mean": iat_mean,
            "iat_std": 0.0,
            "iat_max": max(iats) if iats else 0.0,
            "fwd_iat_mean": iat_mean,
            "is_external_dst": flow.get("is_external_dst", False),
        }
