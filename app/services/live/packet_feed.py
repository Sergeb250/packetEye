"""Real-time packet/event feed for the live capture dashboard (Wireshark-style)."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SUSPICIOUS_PORTS = frozenset({22, 23, 445, 1433, 3389, 4444, 5900, 6667, 31337})
_HIGH_RISK_PORTS = frozenset({4444, 31337, 6667, 1337})


def _parse_ts(value) -> float:
    if value is None:
        return time.time()
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return time.time()


def _is_private_ip(ip_str: str) -> bool:
    try:
        import ipaddress

        ip = ipaddress.ip_address(str(ip_str))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _classify_heuristic(src_ip: str, dst_ip: str, dst_port: int, proto: str, info: str = "") -> str:
    del src_ip
    if dst_port in _HIGH_RISK_PORTS:
        return "critical"
    if not _is_private_ip(dst_ip) and dst_port in _SUSPICIOUS_PORTS:
        return "high"
    if not _is_private_ip(dst_ip) and proto in ("TCP", "UDP"):
        return "medium"
    lower = info.lower()
    if any(x in lower for x in ("scan", "brute", "exploit", "malware", "attack")):
        return "high"
    return "info"


def eve_event_to_row(event: dict) -> dict | None:
    """Map a Suricata EVE event to a Wireshark-style display row."""
    etype = event.get("event_type") or "unknown"
    ts = _parse_ts(event.get("timestamp"))
    src_ip = str(event.get("src_ip") or "")
    dst_ip = str(event.get("dest_ip") or event.get("dst_ip") or "")
    src_port = int(event.get("src_port") or 0)
    dst_port = int(event.get("dest_port") or event.get("dst_port") or 0)
    proto = str(event.get("proto") or "—").upper()

    if etype == "alert":
        alert = event.get("alert") or {}
        sev_map = {1: "critical", 2: "high", 3: "medium"}
        severity = sev_map.get(alert.get("severity"), "high")
        info = str(alert.get("signature") or "Suricata alert")
        length = int(event.get("pkt_len") or 0)
        return _row(ts, src_ip, dst_ip, src_port, dst_port, proto, length, info, severity, "alert", "suricata")

    if etype == "flow":
        flow = event.get("flow") or {}
        bytes_total = int(flow.get("bytes_toserver") or 0) + int(flow.get("bytes_toclient") or 0)
        pkts = int(flow.get("pkts_toserver") or 0) + int(flow.get("pkts_toclient") or 0)
        app = event.get("app_proto") or flow.get("state") or ""
        info = f"Flow end · {pkts} pkts · {bytes_total} B"
        if app:
            info += f" · {app}"
        severity = _classify_heuristic(src_ip, dst_ip, dst_port, proto, info)
        return _row(ts, src_ip, dst_ip, src_port, dst_port, proto, bytes_total, info, severity, "flow", "suricata")

    if etype == "dns":
        dns = event.get("dns") or {}
        q = str(dns.get("rrname") or dns.get("type") or "DNS")
        info = f"DNS {dns.get('type', 'query')}: {q}"
        severity = "medium" if not q.endswith((".local", ".arpa")) else "info"
        return _row(ts, src_ip, dst_ip, src_port, dst_port, "DNS", 0, info, severity, "dns", "suricata")

    if etype == "http":
        http = event.get("http") or {}
        hostname = http.get("hostname") or ""
        method = http.get("http_method") or http.get("method") or "HTTP"
        url = http.get("url") or ""
        info = f"{method} {hostname}{url}".strip()
        severity = _classify_heuristic(src_ip, dst_ip, dst_port, "TCP", info)
        return _row(ts, src_ip, dst_ip, src_port, dst_port, "HTTP", 0, info[:120], severity, "http", "suricata")

    if etype == "tls":
        tls = event.get("tls") or {}
        sni = tls.get("sni") or tls.get("subject") or "TLS handshake"
        info = f"TLS · {sni}"
        severity = "medium" if not _is_private_ip(dst_ip) else "info"
        return _row(ts, src_ip, dst_ip, src_port, dst_port, "TLS", 0, str(sni)[:120], severity, "tls", "suricata")

    if etype in ("anomaly", "drop"):
        info = f"{etype}: {event.get('app_proto') or event.get('reason') or ''}".strip()
        return _row(ts, src_ip, dst_ip, src_port, dst_port, proto, 0, info[:120], "medium", etype, "suricata")

    return None


def scapy_packet_to_row(pkt) -> dict | None:
    """Convert a Scapy packet to a display row."""
    try:
        from scapy.all import ICMP, IP, TCP, UDP  # noqa: WPS433
    except ImportError:
        return None

    ts = float(getattr(pkt, "time", time.time()))
    length = len(pkt)
    src_ip = dst_ip = ""
    src_port = dst_port = 0
    proto = "OTHER"
    info = ""

    if IP in pkt:
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        if TCP in pkt:
            tcp = pkt[TCP]
            proto = "TCP"
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            flags = int(tcp.flags)
            flag_names = []
            if flags & 0x02:
                flag_names.append("SYN")
            if flags & 0x10:
                flag_names.append("ACK")
            if flags & 0x01:
                flag_names.append("FIN")
            if flags & 0x04:
                flag_names.append("RST")
            info = f"TCP [{','.join(flag_names) or 'data'}] len={len(tcp.payload)}"
            if tcp.dport in (80, 443):
                info = f"{'HTTPS' if tcp.dport == 443 else 'HTTP'} {info}"
        elif UDP in pkt:
            udp = pkt[UDP]
            proto = "UDP"
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            info = f"UDP len={len(udp.payload)}"
            if udp.dport == 53 or udp.sport == 53:
                proto = "DNS"
                info = "DNS query/response"
        elif ICMP in pkt:
            proto = "ICMP"
            info = f"ICMP type={pkt[ICMP].type}"
        else:
            info = f"IP proto={ip.proto}"
        severity = _classify_heuristic(src_ip, dst_ip, dst_port, proto, info)
    else:
        info = pkt.summary() if hasattr(pkt, "summary") else "L2 frame"
        severity = "info"

    return _row(ts, src_ip, dst_ip, src_port, dst_port, proto, length, info[:120], severity, "packet", "scapy")


def _row(
    ts: float,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: str,
    length: int,
    info: str,
    severity: str,
    event_type: str,
    source: str,
) -> dict[str, Any]:
    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "length": length,
        "info": info,
        "severity": severity,
        "event_type": event_type,
        "source": source,
    }


class LivePacketFeed:
    """Ring buffer + background ingest from Suricata EVE or Scapy."""

    def __init__(self, max_rows: int = 800):
        self._buffer: deque[dict] = deque(maxlen=max_rows)
        self._lock = threading.Lock()
        self._seq = 0
        self._running = False
        self._mode: str | None = None
        self._interface: str | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._consumer = None
        self._sniffer = None
        self._started_at: float | None = None

    def _append(self, row: dict | None) -> None:
        if not row:
            return
        with self._lock:
            self._seq += 1
            row["id"] = self._seq
            self._buffer.append(row)

    def start(self, config: dict, mode: str, interface: str, eve_path: str | None = None) -> None:
        self.stop()
        self._mode = mode
        self._interface = interface
        self._stop.clear()
        self._running = True
        self._started_at = time.time()

        if mode == "suricata":
            from app.services.live.suricata_consumer import SuricataConsumer

            path = eve_path or config.get("SURICATA_EVE_PATH") or ""
            if not path:
                path = str(Path(str(config.get("SURICATA_LOG_DIR") or "")) / "eve.json")
            self._consumer = SuricataConsumer(path)
            self._thread = threading.Thread(target=self._eve_loop, daemon=True, name="live-packet-eve")
        else:
            self._thread = threading.Thread(
                target=self._scapy_loop, args=(interface,), daemon=True, name="live-packet-scapy"
            )
        self._thread.start()
        logger.info("Live packet feed started (mode=%s iface=%s)", mode, interface)

    def stop(self) -> None:
        self._stop.set()
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                logger.debug("Sniffer stop: %s", exc)
            self._sniffer = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        self._consumer = None

    def _eve_loop(self) -> None:
        import json

        from app.services.live.eve_parser import normalize_eve_event

        while not self._stop.is_set():
            try:
                if self._consumer and self._consumer.eve_path.exists():
                    with open(self._consumer.eve_path, encoding="utf-8", errors="replace") as f:
                        f.seek(self._consumer._offset)
                        for _ in range(200):
                            line = f.readline()
                            if not line:
                                break
                            self._consumer._offset = f.tell()
                            line = line.strip()
                            if not line.startswith("{"):
                                continue
                            try:
                                event = normalize_eve_event(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                            if event:
                                self._append(eve_event_to_row(event))
            except Exception as exc:
                logger.debug("EVE feed error: %s", exc)
            self._stop.wait(0.4)

    def _scapy_loop(self, interface: str) -> None:
        try:
            from scapy.all import sniff  # noqa: WPS433
        except ImportError:
            logger.warning("Scapy not installed — live packet view unavailable for tcpdump mode.")
            return

        def _prn(pkt):
            if self._stop.is_set():
                return
            self._append(scapy_packet_to_row(pkt))

        try:
            sniff(
                iface=interface,
                prn=_prn,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except Exception as exc:
            logger.warning("Scapy sniff failed on %s: %s", interface, exc)
            self._append(
                _row(
                    time.time(), "", "", 0, 0, "—", 0,
                    f"Scapy capture failed: {exc}", "critical", "error", "scapy",
                )
            )

    def poll(self, since_id: int = 0) -> list[dict]:
        with self._lock:
            if since_id <= 0:
                return list(self._buffer)[-200:]
            return [r for r in self._buffer if r["id"] > since_id]

    def status(self) -> dict[str, Any]:
        with self._lock:
            count = len(self._buffer)
            last_id = self._buffer[-1]["id"] if self._buffer else 0
        uptime = round(time.time() - self._started_at, 1) if self._started_at else 0
        return {
            "running": self._running,
            "mode": self._mode,
            "interface": self._interface,
            "buffered": count,
            "last_id": last_id,
            "uptime_seconds": uptime,
        }

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()


_feed = LivePacketFeed()


def start_feed(config: dict, mode: str, interface: str, eve_path: str | None = None) -> None:
    _feed.start(config, mode, interface, eve_path=eve_path)


def stop_feed() -> None:
    _feed.stop()


def poll_packets(since_id: int = 0) -> list[dict]:
    return _feed.poll(since_id)


def feed_status() -> dict:
    return _feed.status()


def clear_feed() -> None:
    _feed.clear()
