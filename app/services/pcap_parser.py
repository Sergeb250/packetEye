"""PCAP ingestion and flow reconstruction using dpkt."""

import hashlib
import ipaddress
import logging
import math
import os
import socket
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import dpkt

logger = logging.getLogger(__name__)

PCAP_MAGIC = {0xA1B2C3D4, 0xA1B23C4D, 0xD4C3B2A1, 0x4D3CB2A1}
PCAPNG_MAGIC = 0x0A0D0D0A

RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def is_external_ip(ip_str: str) -> bool:
    return not is_private_ip(ip_str)


@dataclass
class FlowState:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime | None = None
    end_time: datetime | None = None
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    packet_times: list = field(default_factory=list)
    dns_queries: set = field(default_factory=set)
    http_hosts: set = field(default_factory=set)
    user_agents: set = field(default_factory=set)
    tls_sni: str | None = None
    ja3_hash: str | None = None
    ja3s_hash: str | None = None
    tls_cert_subject: str | None = None
    tls_cert_issuer: str | None = None
    tls_cert_san: set = field(default_factory=set)
    application_layer: str | None = None
    tcp_seen_syn: bool = False
    tcp_closed: bool = False

    def flow_key(self):
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)


def _ts_to_datetime(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _compute_ja3(tls: dpkt.ssl.TLSClientHello) -> str | None:
    try:
        ciphers = "-".join(str(c) for c in tls.ciphers)
        exts = []
        curves = []
        ec_formats = []
        for ext_type, ext_data in tls.extensions:
            exts.append(str(ext_type))
            if ext_type == 10:  # supported_groups
                curves = [str(struct.unpack(">H", ext_data[i : i + 2])[0]) for i in range(0, len(ext_data), 2)]
            elif ext_type == 11:
                ec_formats = [str(b) for b in ext_data]
        ja3_string = f"{tls.version},{ciphers},{','.join(exts)},{','.join(curves)},{','.join(ec_formats)}"
        return hashlib.md5(ja3_string.encode()).hexdigest()
    except Exception:
        return None


def _extract_sni(data: bytes) -> str | None:
    try:
        if len(data) < 5:
            return None
        if data[0] != 0x16:
            return None
        pos = 5
        if pos >= len(data):
            return None
        if data[pos] != 0x01:
            return None
        pos += 4 + 2 + 32
        if pos + 1 >= len(data):
            return None
        sess_len = data[pos]
        pos += 1 + sess_len
        if pos + 2 >= len(data):
            return None
        cs_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2 + cs_len
        if pos + 1 >= len(data):
            return None
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 >= len(data):
            return None
        ext_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2
        end = pos + ext_len
        while pos + 4 <= end and pos + 4 <= len(data):
            etype, elen = struct.unpack("!HH", data[pos : pos + 4])
            pos += 4
            edata = data[pos : pos + elen]
            pos += elen
            if etype == 0:  # SNI
                if len(edata) > 5:
                    name_len = struct.unpack("!H", edata[3:5])[0]
                    return edata[5 : 5 + name_len].decode("utf-8", errors="ignore")
        return None
    except Exception:
        return None


class PCAPParser:
    UDP_IDLE_TIMEOUT = 60.0
    CHUNK_SIZE = 1024 * 1024

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.flows: dict[tuple, FlowState] = {}
        self.arp_events: list[dict] = []
        self.observables: dict[tuple, dict] = {}

    def parse(self, progress_callback=None) -> dict[str, Any]:
        file_size = max(1, os.path.getsize(self.file_path))
        processed = 0

        with open(self.file_path, "rb") as f:
            header = f.read(4)
            f.seek(0)
            if len(header) >= 4:
                magic = struct.unpack("I", header)[0]
                if magic == PCAPNG_MAGIC:
                    reader = dpkt.pcapng.Reader(f)
                else:
                    reader = dpkt.pcap.Reader(f)
            else:
                raise ValueError("File too small to be a valid PCAP")

            for ts, buf in reader:
                processed += len(buf)
                if progress_callback and processed % (self.CHUNK_SIZE * 10) == 0:
                    progress_callback(min(24, int(processed / file_size * 24)))
                try:
                    self._process_packet(ts, buf)
                except Exception as exc:
                    logger.debug("Skipping malformed packet: %s", exc)

        self._finalize_udp_flows()
        return self._build_output()

    def _get_or_create_flow(
        self, src_ip, dst_ip, src_port, dst_port, protocol, ts
    ) -> FlowState:
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        rev_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        if key in self.flows:
            flow = self.flows[key]
        elif rev_key in self.flows:
            flow = self.flows[rev_key]
        else:
            flow = FlowState(src_ip, dst_ip, src_port, dst_port, protocol)
            self.flows[key] = flow

        dt = _ts_to_datetime(ts)
        if flow.start_time is None:
            flow.start_time = dt
        flow.end_time = dt
        flow.packet_times.append(ts)
        return flow

    def _process_packet(self, ts: float, buf: bytes):
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except dpkt.UnpackError:
            return

        if isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            self.arp_events.append(
                {
                    "op": arp.op,
                    "sender_mac": eth.src.hex(":"),
                    "sender_ip": socket.inet_ntoa(arp.spa),
                    "target_ip": socket.inet_ntoa(arp.tpa),
                    "timestamp": ts,
                }
            )
            return

        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            return

        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        self._track_observable("ip", src_ip, ts)
        self._track_observable("ip", dst_ip, ts)

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            flow = self._get_or_create_flow(
                src_ip, dst_ip, tcp.sport, tcp.dport, "TCP", ts
            )
            payload_len = len(tcp.data)
            if flow.src_ip == src_ip:
                flow.bytes_sent += payload_len
                flow.packets_sent += 1
            else:
                flow.bytes_recv += payload_len
                flow.packets_recv += 1

            if tcp.flags & dpkt.tcp.TH_SYN:
                flow.tcp_seen_syn = True
            if tcp.flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
                flow.tcp_closed = True

            self._inspect_tcp_payload(flow, tcp, src_ip, dst_ip, ts)

        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            flow = self._get_or_create_flow(
                src_ip, dst_ip, udp.sport, udp.dport, "UDP", ts
            )
            payload_len = len(udp.data)
            if flow.src_ip == src_ip:
                flow.bytes_sent += payload_len
                flow.packets_sent += 1
            else:
                flow.bytes_recv += payload_len
                flow.packets_recv += 1
            self._inspect_udp_payload(flow, udp, src_ip, dst_ip)

        elif isinstance(ip.data, dpkt.icmp.ICMP):
            flow = self._get_or_create_flow(src_ip, dst_ip, 0, 0, "ICMP", ts)
            flow.application_layer = "ICMP"
            flow.bytes_sent += len(ip.data.data) if ip.data.data else 0
            flow.packets_sent += 1

    def _inspect_tcp_payload(self, flow, tcp, src_ip, dst_ip, ts):
        data = tcp.data
        if not data:
            return

        dport = tcp.dport if flow.src_ip == src_ip else tcp.sport

        if dport == 443 or dport == 8443 or (len(data) > 0 and data[0] == 0x16):
            flow.application_layer = "TLS"
            sni = _extract_sni(data)
            if sni:
                flow.tls_sni = sni
                self._track_observable("domain", sni, ts)
            try:
                records = dpkt.ssl.TLSMultiRecord(data)
                for rec in records:
                    if isinstance(rec, dpkt.ssl.TLSClientHello):
                        flow.ja3_hash = _compute_ja3(rec) or flow.ja3_hash
                        for ext_type, ext_data in rec.extensions:
                            if ext_type == 0 and len(ext_data) > 5:
                                name_len = struct.unpack("!H", ext_data[3:5])[0]
                                sni_val = ext_data[5 : 5 + name_len].decode("utf-8", errors="ignore")
                                flow.tls_sni = sni_val
                                self._track_observable("domain", sni_val, ts)
            except Exception:
                pass

        elif dport in (80, 8080, 8000) or data.startswith(b"GET ") or data.startswith(b"POST "):
            flow.application_layer = "HTTP"
            try:
                http = dpkt.http.Request(data) if data.startswith(b"GET") or data.startswith(b"POST") else None
                if http and http.headers.get("host"):
                    host = http.headers["host"]
                    flow.http_hosts.add(host)
                    self._track_observable("domain", host.split(":")[0], ts)
                if http and http.headers.get("user-agent"):
                    ua = http.headers["user-agent"]
                    flow.user_agents.add(ua)
                    self._track_observable("user_agent", ua, ts)
            except Exception:
                if b"Host:" in data:
                    for line in data.split(b"\r\n"):
                        if line.lower().startswith(b"host:"):
                            host = line.split(b":", 1)[1].strip().decode("utf-8", errors="ignore")
                            flow.http_hosts.add(host)
                            self._track_observable("domain", host.split(":")[0], ts)

        elif dport == 22:
            flow.application_layer = "SSH"
        elif dport == 445:
            flow.application_layer = "SMB"
        elif dport == 3389:
            flow.application_layer = "RDP"

    def _inspect_udp_payload(self, flow, udp, src_ip, dst_ip):
        if udp.dport == 53 or udp.sport == 53:
            flow.application_layer = "DNS"
            try:
                dns = dpkt.dns.DNS(udp.data)
                if dns.qd:
                    for q in dns.qd:
                        name = q.name
                        if name:
                            flow.dns_queries.add(name)
                            self._track_observable("domain", name, flow.packet_times[-1] if flow.packet_times else 0)
            except Exception:
                pass

    def _track_observable(self, obs_type: str, value: str, ts):
        if not value:
            return
        key = (obs_type, value)
        if key not in self.observables:
            self.observables[key] = {
                "type": obs_type,
                "value": value,
                "first_seen": _ts_to_datetime(ts) if isinstance(ts, (int, float)) else utcnow_fallback(),
                "occurrence_count": 0,
            }
        self.observables[key]["occurrence_count"] += 1

    def _finalize_udp_flows(self):
        pass

    def _build_output(self) -> dict[str, Any]:
        flow_list = []
        for key, flow in self.flows.items():
            duration_ms = 0
            if flow.start_time and flow.end_time:
                duration_ms = int((flow.end_time - flow.start_time).total_seconds() * 1000)

            iat_mean, iat_std = 0.0, 0.0
            if len(flow.packet_times) > 1:
                iats = [
                    flow.packet_times[i + 1] - flow.packet_times[i]
                    for i in range(len(flow.packet_times) - 1)
                ]
                iat_mean = sum(iats) / len(iats)
                if len(iats) > 1:
                    iat_std = math.sqrt(sum((x - iat_mean) ** 2 for x in iats) / len(iats))

            flow_list.append(
                {
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "start_time": flow.start_time,
                    "end_time": flow.end_time,
                    "duration_ms": duration_ms,
                    "bytes_sent": flow.bytes_sent,
                    "bytes_recv": flow.bytes_recv,
                    "packets_sent": flow.packets_sent,
                    "packets_recv": flow.packets_recv,
                    "application_layer": flow.application_layer,
                    "dns_queries": list(flow.dns_queries),
                    "http_hosts": list(flow.http_hosts),
                    "user_agents": list(flow.user_agents),
                    "tls_sni": flow.tls_sni,
                    "ja3_hash": flow.ja3_hash,
                    "ja3s_hash": flow.ja3s_hash,
                    "tls_cert_subject": flow.tls_cert_subject,
                    "tls_cert_issuer": flow.tls_cert_issuer,
                    "tls_cert_san": list(flow.tls_cert_san),
                    "iat_mean": iat_mean,
                    "iat_std": iat_std,
                    "is_external_dst": is_external_ip(flow.dst_ip),
                }
            )

        return {
            "flows": flow_list,
            "observables": list(self.observables.values()),
            "arp_events": self.arp_events,
        }


def utcnow_fallback():
    return datetime.now(timezone.utc)


def validate_pcap_magic(file_path: str) -> bool:
    import os

    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return False
            val = struct.unpack("I", magic)[0]
            return val in PCAP_MAGIC or val == PCAPNG_MAGIC
    except OSError:
        return False

