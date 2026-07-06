"""Shared feature extraction for CIC-IDS2017 training and packetEye inference."""

import ipaddress
import json
import logging
import math
from pathlib import Path

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "dst_port",
    "duration_ms_log",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes_log",
    "bwd_bytes_log",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "pkt_size_avg",
    "down_up_ratio",
    "iat_mean",
    "iat_std",
    "iat_max",
    "fwd_iat_mean",
    "dst_port_entropy",
    "is_external_dst",
    "time_of_day_hour",
    "protocol_encoded",
]

FEATURE_SCHEMA_VERSION = 3

PROTOCOL_MAP = {"TCP": 1, "UDP": 2, "ICMP": 3, "tcp": 1, "udp": 2, "icmp": 3}
# CIC-IDS2017 numeric protocol identifiers (IP protocol numbers)
CIC_PROTOCOL_NUM_MAP = {6: 1, 17: 2, 1: 3}

# CIC-IDS2017 column names (with common variants)
CIC_COLUMN_ALIASES = {
    "dst_port": ["Destination Port", "Dst Port", "dst_port", "destination_port"],
    "flow_duration": ["Flow Duration", "flow_duration"],
    "fwd_packets": ["Total Fwd Packets", "Total Fwd Packet", "fwd_packets"],
    "bwd_packets": ["Total Backward Packets", "Total Bwd Packets", "bwd_packets"],
    "fwd_bytes": ["Total Length of Fwd Packets", "Fwd Packet Length Total", "fwd_bytes"],
    "bwd_bytes": ["Total Length of Bwd Packets", "Bwd Packet Length Total", "bwd_bytes"],
    "flow_bytes_per_s": ["Flow Bytes/s", "Flow Bytes/s ", "flow_bytes_s"],
    "flow_packets_per_s": ["Flow Packets/s", "Flow Packets/s ", "flow_packets_s"],
    "iat_mean": ["Flow IAT Mean", "flow_iat_mean"],
    "iat_std": ["Flow IAT Std", "Flow IAT Standard Deviation", "flow_iat_std"],
    "iat_max": ["Flow IAT Max", "flow_iat_max"],
    "fwd_iat_mean": ["Fwd IAT Mean", "fwd_iat_mean"],
    "protocol": ["Protocol", "protocol"],
    "timestamp": ["Timestamp", "timestamp", "Flow Start Time"],
}


def _resolve_cic_column(df: pd.DataFrame, aliases: list[str]) -> str | None:
    cols = {c.strip(): c for c in df.columns}
    for alias in aliases:
        if alias in cols:
            return cols[alias]
        for col in df.columns:
            if col.strip().lower() == alias.lower():
                return col
    return None


from app.services.net_utils import is_external_ip, is_internal_ip


def _is_private_ip(ip_str: str) -> bool:
    return is_internal_ip(ip_str)


def _port_entropy(flows_df: pd.DataFrame) -> dict:
    entropy_by_src = {}
    if flows_df.empty or "src_ip" not in flows_df.columns:
        return entropy_by_src
    for src, group in flows_df.groupby("src_ip"):
        ports = group["dst_port"].tolist() if "dst_port" in group.columns else []
        if not ports:
            entropy_by_src[src] = 0.0
            continue
        counts: dict = {}
        for p in ports:
            counts[p] = counts.get(p, 0) + 1
        total = len(ports)
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
        entropy_by_src[src] = entropy
    return entropy_by_src


def _encode_protocol(protocol: str | int) -> int:
    if protocol is None:
        return 0
    if isinstance(protocol, (int, float)) and not isinstance(protocol, bool):
        num = int(protocol)
        if num in CIC_PROTOCOL_NUM_MAP:
            return CIC_PROTOCOL_NUM_MAP[num]
        return 0
    p = str(protocol).upper()
    if p in PROTOCOL_MAP:
        return PROTOCOL_MAP[p]
    if p.isdigit():
        return _encode_protocol(int(p))
    return PROTOCOL_MAP.get(str(protocol).lower(), 0)


def _safe_float(val, default=0.0) -> float:
    try:
        if val is None or (isinstance(val, float) and np.isnan(val)):
            return default
        return float(val)
    except (TypeError, ValueError):
        return default


def cic_duration_us_to_ms(duration_us: float) -> float:
    """CIC-IDS2017 Flow Duration is in microseconds; packetEye uses milliseconds."""
    return max(0.0, duration_us) / 1000.0


def cic_iat_us_to_seconds(iat_us: float) -> float:
    """CIC IAT columns are in microseconds; packetEye parser uses seconds."""
    return max(0.0, iat_us) / 1_000_000.0


def _hour_from_timestamp(value) -> int:
    if value is None:
        return 12
    try:
        return pd.to_datetime(value).hour
    except Exception:
        return 12


def _flow_row_features(f: dict, port_entropy: dict) -> dict:
    bytes_sent = _safe_float(f.get("bytes_sent", 0))
    bytes_recv = _safe_float(f.get("bytes_recv", 0))
    packets_sent = int(_safe_float(f.get("packets_sent", 0)))
    packets_recv = int(_safe_float(f.get("packets_recv", 0)))
    duration_ms = _safe_float(f.get("duration_ms", 0))
    duration_s = max(duration_ms / 1000.0, 1e-6)

    start = f.get("start_time")
    hour = 12
    if start is not None:
        if hasattr(start, "hour"):
            hour = start.hour
        elif isinstance(start, str):
            hour = _hour_from_timestamp(start)

    dst_ip = f.get("dst_ip", "")
    is_external = f.get("is_external_dst")
    if is_external is None:
        is_external = is_external_ip(dst_ip)

    bytes_total = bytes_sent + bytes_recv
    packets_total = packets_sent + packets_recv

    # Live consumers (Suricata) track rolling per-src entropy across the whole
    # session; that beats recomputing it from a tiny 2-second batch.
    precomputed_entropy = f.get("dst_port_entropy")
    if precomputed_entropy is not None:
        entropy = _safe_float(precomputed_entropy)
    else:
        entropy = port_entropy.get(f.get("src_ip"), 0.0)

    return {
        "flow_id": f.get("id"),
        "dst_port": int(_safe_float(f.get("dst_port", 0))),
        "duration_ms_log": math.log1p(duration_ms),
        "fwd_packets": packets_sent,
        "bwd_packets": packets_recv,
        "fwd_bytes_log": math.log1p(bytes_sent),
        "bwd_bytes_log": math.log1p(bytes_recv),
        "flow_bytes_per_s": bytes_total / duration_s,
        "flow_packets_per_s": packets_total / duration_s,
        "fwd_pkt_len_mean": bytes_sent / max(packets_sent, 1),
        "bwd_pkt_len_mean": bytes_recv / max(packets_recv, 1),
        "pkt_size_avg": bytes_total / max(packets_total, 1),
        "down_up_ratio": packets_recv / max(packets_sent, 1),
        "iat_mean": _safe_float(f.get("iat_mean", 0)),
        "iat_std": _safe_float(f.get("iat_std", 0)),
        "iat_max": _safe_float(f.get("iat_max", 0)),
        "fwd_iat_mean": _safe_float(f.get("fwd_iat_mean", 0)),
        "dst_port_entropy": entropy,
        "is_external_dst": 1 if is_external else 0,
        "time_of_day_hour": hour,
        "protocol_encoded": _encode_protocol(f.get("protocol", "")),
    }


def build_feature_matrix(flows: list) -> pd.DataFrame:
    if not flows:
        return pd.DataFrame(columns=["flow_id"] + FEATURE_NAMES)

    df = pd.DataFrame(flows)
    port_entropy = _port_entropy(df)
    rows = [_flow_row_features(f if isinstance(f, dict) else f.to_dict(), port_entropy) for f in flows]
    return pd.DataFrame(rows)


def build_feature_matrix_from_cic(df: pd.DataFrame) -> pd.DataFrame:
    """Map CIC-IDS2017 Parquet rows to the shared feature vector."""
    if df.empty:
        return pd.DataFrame(columns=["flow_id"] + FEATURE_NAMES)

    resolved = {key: _resolve_cic_column(df, aliases) for key, aliases in CIC_COLUMN_ALIASES.items()}

    missing = [k for k, v in resolved.items() if v is None and k not in ("fwd_iat_mean", "timestamp", "protocol")]
    if missing:
        logger.warning("CIC columns not found (will use 0): %s", missing)

    protocol_col = resolved.get("protocol")
    timestamp_col = resolved.get("timestamp")

    rows = []
    for idx, row in df.iterrows():
        duration_us = _safe_float(row.get(resolved["flow_duration"])) if resolved["flow_duration"] else 0.0
        duration_ms = cic_duration_us_to_ms(duration_us)
        duration_s = max(duration_ms / 1000.0, 1e-6)

        fwd_bytes = _safe_float(row.get(resolved["fwd_bytes"])) if resolved["fwd_bytes"] else 0.0
        bwd_bytes = _safe_float(row.get(resolved["bwd_bytes"])) if resolved["bwd_bytes"] else 0.0
        fwd_pkts = _safe_float(row.get(resolved["fwd_packets"])) if resolved["fwd_packets"] else 0.0
        bwd_pkts = _safe_float(row.get(resolved["bwd_packets"])) if resolved["bwd_packets"] else 0.0

        flow_bytes_s = (
            _safe_float(row.get(resolved["flow_bytes_per_s"]))
            if resolved["flow_bytes_per_s"]
            else (fwd_bytes + bwd_bytes) / duration_s
        )
        flow_pkts_s = (
            _safe_float(row.get(resolved["flow_packets_per_s"]))
            if resolved["flow_packets_per_s"]
            else (fwd_pkts + bwd_pkts) / duration_s
        )

        proto_val = row.get(protocol_col) if protocol_col else 6
        ts_val = row.get(timestamp_col) if timestamp_col else None

        rows.append(
            {
                "flow_id": idx,
                "dst_port": int(_safe_float(row.get(resolved["dst_port"])) if resolved["dst_port"] else 0),
                "duration_ms_log": math.log1p(duration_ms),
                "fwd_packets": fwd_pkts,
                "bwd_packets": bwd_pkts,
                "fwd_bytes_log": math.log1p(fwd_bytes),
                "bwd_bytes_log": math.log1p(bwd_bytes),
                "flow_bytes_per_s": flow_bytes_s,
                "flow_packets_per_s": flow_pkts_s,
                "fwd_pkt_len_mean": fwd_bytes / max(fwd_pkts, 1),
                "bwd_pkt_len_mean": bwd_bytes / max(bwd_pkts, 1),
                "pkt_size_avg": (fwd_bytes + bwd_bytes) / max(fwd_pkts + bwd_pkts, 1),
                "down_up_ratio": bwd_pkts / max(fwd_pkts, 1),
                "iat_mean": cic_iat_us_to_seconds(
                    _safe_float(row.get(resolved["iat_mean"])) if resolved["iat_mean"] else 0.0
                ),
                "iat_std": cic_iat_us_to_seconds(
                    _safe_float(row.get(resolved["iat_std"])) if resolved["iat_std"] else 0.0
                ),
                "iat_max": cic_iat_us_to_seconds(
                    _safe_float(row.get(resolved["iat_max"])) if resolved["iat_max"] else 0.0
                ),
                "fwd_iat_mean": cic_iat_us_to_seconds(
                    _safe_float(row.get(resolved["fwd_iat_mean"])) if resolved["fwd_iat_mean"] else 0.0
                ),
                "dst_port_entropy": 0.0,
                "is_external_dst": 0,
                "time_of_day_hour": _hour_from_timestamp(ts_val),
                "protocol_encoded": _encode_protocol(proto_val),
            }
        )

    result = pd.DataFrame(rows)

    src_col = _resolve_cic_column(df, ["Source IP", "Src IP", "src_ip", "source_ip"])
    dst_col = _resolve_cic_column(df, ["Destination IP", "Dst IP", "dst_ip", "destination_ip"])
    port_col = resolved.get("dst_port")

    if src_col and port_col:
        entropy_map = _port_entropy(
            pd.DataFrame(
                {
                    "src_ip": df[src_col].astype(str),
                    "dst_port": df[port_col],
                }
            )
        )
        result["dst_port_entropy"] = (
            df[src_col].astype(str).map(entropy_map).fillna(0.0).to_numpy()
        )

    if dst_col:
        result["is_external_dst"] = (
            df[dst_col].astype(str).apply(lambda ip: 1 if is_external_ip(ip) else 0).to_numpy()
        )

    return result


def validate_feature_schema(loaded_names: list[str], expected: list[str] | None = None) -> None:
    """A saved schema is valid if every feature it names can still be produced.

    Older models trained on a subset of the current FEATURE_NAMES stay usable:
    inference selects exactly the columns the model was trained on.
    """
    expected = expected or FEATURE_NAMES
    if not loaded_names:
        raise ValueError("Feature schema is empty")
    unknown = [n for n in loaded_names if n not in expected]
    if unknown:
        raise ValueError(
            f"Feature schema mismatch: schema names {unknown} are not produced "
            f"by the current feature builder ({expected})"
        )


def save_feature_schema(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"feature_names": FEATURE_NAMES, "version": FEATURE_SCHEMA_VERSION}, f, indent=2)


def load_feature_schema(path: Path) -> list[str]:
    if not path.exists():
        return FEATURE_NAMES
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    names = data.get("feature_names", FEATURE_NAMES)
    validate_feature_schema(names, FEATURE_NAMES)
    return names
