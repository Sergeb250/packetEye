"""Map Suricata EVE flow events to packetEye flow dicts."""

import ipaddress
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _parse_ts(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(ip_str))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def eve_flow_to_flow_dict(eve_event: dict, flow_id: str | None = None) -> dict | None:
    """Convert a Suricata EVE flow event to a packetEye flow dictionary."""
    if eve_event.get("event_type") != "flow":
        return None

    flow = eve_event.get("flow") or {}
    start = _parse_ts(flow.get("start") or eve_event.get("timestamp"))
    end = _parse_ts(flow.get("end") or eve_event.get("timestamp"))
    duration_ms = 0
    if start and end:
        duration_ms = max(0, int((end - start).total_seconds() * 1000))

    bytes_sent = int(flow.get("bytes_toserver") or 0)
    bytes_recv = int(flow.get("bytes_toclient") or 0)
    packets_sent = int(flow.get("pkts_toserver") or 0)
    packets_recv = int(flow.get("pkts_toclient") or 0)

    proto = str(eve_event.get("proto") or "TCP").upper()
    dst_ip = str(eve_event.get("dest_ip") or eve_event.get("dst_ip") or "")

    return {
        "id": flow_id or eve_event.get("flow_id") or eve_event.get("tx_id"),
        "src_ip": str(eve_event.get("src_ip") or ""),
        "dst_ip": dst_ip,
        "src_port": int(eve_event.get("src_port") or 0),
        "dst_port": int(eve_event.get("dest_port") or eve_event.get("dst_port") or 0),
        "protocol": proto,
        "start_time": start,
        "end_time": end,
        "duration_ms": duration_ms,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "packets_sent": packets_sent,
        "packets_recv": packets_recv,
        "iat_mean": float(flow.get("mean_delta") or 0),
        "iat_std": 0.0,
        "iat_max": 0.0,
        "fwd_iat_mean": 0.0,
        "is_external_dst": not _is_private_ip(dst_ip),
    }


# Suricata alert severity: 1 is most severe.
_SURICATA_SEVERITY_MAP = {1: "high", 2: "medium", 3: "low"}


def eve_alert_to_alert_dict(eve_event: dict) -> dict | None:
    """Convert a Suricata EVE alert (signature hit) to a packetEye alert dict."""
    if eve_event.get("event_type") != "alert":
        return None

    alert = eve_event.get("alert") or {}
    signature = str(alert.get("signature") or "").strip()
    if not signature:
        return None

    ts = _parse_ts(eve_event.get("timestamp"))
    return {
        "signature": signature,
        "signature_id": alert.get("signature_id"),
        "category": str(alert.get("category") or ""),
        "severity": _SURICATA_SEVERITY_MAP.get(alert.get("severity"), "medium"),
        "action": str(alert.get("action") or ""),
        "src_ip": str(eve_event.get("src_ip") or ""),
        "dst_ip": str(eve_event.get("dest_ip") or eve_event.get("dst_ip") or ""),
        "src_port": int(eve_event.get("src_port") or 0),
        "dst_port": int(eve_event.get("dest_port") or eve_event.get("dst_port") or 0),
        "protocol": str(eve_event.get("proto") or "TCP").upper(),
        "app_proto": str(eve_event.get("app_proto") or ""),
        "timestamp": ts,
    }
