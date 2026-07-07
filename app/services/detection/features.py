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
FULL_FEATURE_SCHEMA_VERSION = 4

# ---------------------------------------------------------------------------
# Full CIC-IDS2017 feature set (schema v4): every numeric flow column from the
# Network-Flows parquet plus destination_port and the encoded protocol — 78
# features. Canonical units are CIC-native (durations/IAT/active/idle in
# MICROSECONDS): training is then a pure passthrough, and live inference
# converts in build_full_feature_matrix(). The scaler absorbs the unit choice
# as long as train and inference agree. Note: "fwd_iat_mean" here is µs while
# the legacy v3 feature of the same name is seconds — the two sets never mix
# (a model is entirely legacy or entirely full).
# ---------------------------------------------------------------------------
CIC_FULL_COLUMN_MAP: dict[str, list[str]] = {
    "destination_port": ["destination_port", "Destination Port", "Dst Port"],
    "protocol_encoded": ["protocol", "Protocol"],
    "flow_duration": ["Flow Duration"],
    "total_fwd_packets": ["Total Fwd Packets", "Total Fwd Packet"],
    "total_backward_packets": ["Total Backward Packets", "Total Bwd Packets", "Total Bwd packets"],
    "total_length_of_fwd_packets": ["Total Length of Fwd Packets", "Fwd Packet Length Total", "Total Length of Fwd Packet"],
    "total_length_of_bwd_packets": ["Total Length of Bwd Packets", "Bwd Packet Length Total", "Total Length of Bwd Packet"],
    "fwd_packet_length_max": ["Fwd Packet Length Max"],
    "fwd_packet_length_min": ["Fwd Packet Length Min"],
    "fwd_packet_length_mean": ["Fwd Packet Length Mean"],
    "fwd_packet_length_std": ["Fwd Packet Length Std"],
    "bwd_packet_length_max": ["Bwd Packet Length Max"],
    "bwd_packet_length_min": ["Bwd Packet Length Min"],
    "bwd_packet_length_mean": ["Bwd Packet Length Mean"],
    "bwd_packet_length_std": ["Bwd Packet Length Std"],
    "flow_bytes_per_s": ["Flow Bytes/s"],
    "flow_packets_per_s": ["Flow Packets/s"],
    "flow_iat_mean": ["Flow IAT Mean"],
    "flow_iat_std": ["Flow IAT Std", "Flow IAT Standard Deviation"],
    "flow_iat_max": ["Flow IAT Max"],
    "flow_iat_min": ["Flow IAT Min"],
    "fwd_iat_total": ["Fwd IAT Total"],
    "fwd_iat_mean": ["Fwd IAT Mean"],
    "fwd_iat_std": ["Fwd IAT Std"],
    "fwd_iat_max": ["Fwd IAT Max"],
    "fwd_iat_min": ["Fwd IAT Min"],
    "bwd_iat_total": ["Bwd IAT Total"],
    "bwd_iat_mean": ["Bwd IAT Mean"],
    "bwd_iat_std": ["Bwd IAT Std"],
    "bwd_iat_max": ["Bwd IAT Max"],
    "bwd_iat_min": ["Bwd IAT Min"],
    "fwd_psh_flags": ["Fwd PSH Flags"],
    "bwd_psh_flags": ["Bwd PSH Flags"],
    "fwd_urg_flags": ["Fwd URG Flags"],
    "bwd_urg_flags": ["Bwd URG Flags"],
    "fwd_header_length": ["Fwd Header Length"],
    "bwd_header_length": ["Bwd Header Length"],
    "fwd_packets_per_s": ["Fwd Packets/s"],
    "bwd_packets_per_s": ["Bwd Packets/s"],
    "min_packet_length": ["Min Packet Length", "Packet Length Min"],
    "max_packet_length": ["Max Packet Length", "Packet Length Max"],
    "packet_length_mean": ["Packet Length Mean"],
    "packet_length_std": ["Packet Length Std"],
    "packet_length_variance": ["Packet Length Variance"],
    "fin_flag_count": ["FIN Flag Count"],
    "syn_flag_count": ["SYN Flag Count"],
    "rst_flag_count": ["RST Flag Count"],
    "psh_flag_count": ["PSH Flag Count"],
    "ack_flag_count": ["ACK Flag Count"],
    "urg_flag_count": ["URG Flag Count"],
    "cwe_flag_count": ["CWE Flag Count", "CWR Flag Count"],
    "ece_flag_count": ["ECE Flag Count"],
    "down_up_ratio": ["Down/Up Ratio"],
    "average_packet_size": ["Average Packet Size", "Avg Packet Size"],
    "avg_fwd_segment_size": ["Avg Fwd Segment Size"],
    "avg_bwd_segment_size": ["Avg Bwd Segment Size"],
    "fwd_avg_bytes_per_bulk": ["Fwd Avg Bytes/Bulk", "Fwd Bytes/Bulk Avg"],
    "fwd_avg_packets_per_bulk": ["Fwd Avg Packets/Bulk", "Fwd Packet/Bulk Avg"],
    "fwd_avg_bulk_rate": ["Fwd Avg Bulk Rate", "Fwd Bulk Rate Avg"],
    "bwd_avg_bytes_per_bulk": ["Bwd Avg Bytes/Bulk", "Bwd Bytes/Bulk Avg"],
    "bwd_avg_packets_per_bulk": ["Bwd Avg Packets/Bulk", "Bwd Packet/Bulk Avg"],
    "bwd_avg_bulk_rate": ["Bwd Avg Bulk Rate", "Bwd Bulk Rate Avg"],
    "subflow_fwd_packets": ["Subflow Fwd Packets"],
    "subflow_fwd_bytes": ["Subflow Fwd Bytes"],
    "subflow_bwd_packets": ["Subflow Bwd Packets"],
    "subflow_bwd_bytes": ["Subflow Bwd Bytes"],
    "init_win_bytes_forward": ["Init_Win_bytes_forward", "FWD Init Win Bytes"],
    "init_win_bytes_backward": ["Init_Win_bytes_backward", "Bwd Init Win Bytes"],
    "act_data_pkt_fwd": ["act_data_pkt_fwd", "Fwd Act Data Pkts"],
    "min_seg_size_forward": ["min_seg_size_forward", "Fwd Seg Size Min"],
    "active_mean": ["Active Mean"],
    "active_std": ["Active Std"],
    "active_max": ["Active Max"],
    "active_min": ["Active Min"],
    "idle_mean": ["Idle Mean"],
    "idle_std": ["Idle Std"],
    "idle_max": ["Idle Max"],
    "idle_min": ["Idle Min"],
}

CIC_FULL_FEATURE_NAMES = list(CIC_FULL_COLUMN_MAP.keys())

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


def build_cic_full_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """CIC parquet/CSV rows → full 78-feature matrix (schema v4).

    Pure passthrough in CIC-native units (µs durations/IATs) — no conversion
    means no conversion bugs; the scaler normalizes units away. inf values
    (zero-duration Flow Bytes/s rows) become NaN for the cleaning mask.
    """
    if df.empty:
        return pd.DataFrame(columns=["flow_id"] + CIC_FULL_FEATURE_NAMES)

    out = pd.DataFrame(index=df.index)
    missing: list[str] = []
    for name, aliases in CIC_FULL_COLUMN_MAP.items():
        col = _resolve_cic_column(df, aliases)
        if name == "protocol_encoded":
            out[name] = (
                df[col].map(_encode_protocol).astype(float) if col is not None else 0.0
            )
            continue
        if col is None:
            missing.append(name)
            out[name] = np.nan
            continue
        out[name] = pd.to_numeric(df[col], errors="coerce")
    if missing:
        logger.warning("CIC full-feature columns not found (NaN → cleaned/filled): %s", missing)

    out = out.replace([np.inf, -np.inf], np.nan)
    out.insert(0, "flow_id", np.arange(len(out)))
    return out.reset_index(drop=True)


def build_cic_matrix(df: pd.DataFrame, feature_set: str = "legacy") -> pd.DataFrame:
    """Dispatch CIC training/eval feature building by feature set."""
    if feature_set == "full":
        return build_cic_full_feature_matrix(df)
    return build_feature_matrix_from_cic(df)


def _fill_value(fill: dict, name: str) -> float:
    return _safe_float(fill.get(name), 0.0)


def _full_row_from_flow(f: dict, fill: dict) -> dict:
    """packetEye flow dict → one full-feature row (CIC-native units).

    Producers emit optional extended keys (pkt_len_min, syn_count,
    init_win_fwd, …) where derivable; everything else falls back to the
    per-feature training median in `fill` so unmeasurable dimensions sit at
    "typical benign" instead of 0.
    """
    bytes_sent = _safe_float(f.get("bytes_sent", 0))
    bytes_recv = _safe_float(f.get("bytes_recv", 0))
    packets_sent = _safe_float(f.get("packets_sent", 0))
    packets_recv = _safe_float(f.get("packets_recv", 0))
    duration_ms = _safe_float(f.get("duration_ms", 0))
    duration_us = max(0.0, duration_ms) * 1000.0
    duration_s = max(duration_ms / 1000.0, 1e-6)
    bytes_total = bytes_sent + bytes_recv
    packets_total = packets_sent + packets_recv

    def val(key: str, canonical: str) -> float:
        v = f.get(key)
        return _safe_float(v) if v is not None else _fill_value(fill, canonical)

    def val_us(key: str, canonical: str) -> float:
        """Producer keys are in seconds; canonical full features are µs."""
        v = f.get(key)
        return _safe_float(v) * 1_000_000.0 if v is not None else _fill_value(fill, canonical)

    fwd_mean = bytes_sent / max(packets_sent, 1)
    bwd_mean = bytes_recv / max(packets_recv, 1)
    pkt_mean = bytes_total / max(packets_total, 1)
    pkt_len_std = f.get("pkt_len_std")

    return {
        "flow_id": f.get("id"),
        "destination_port": _safe_float(f.get("dst_port", 0)),
        "protocol_encoded": float(_encode_protocol(f.get("protocol", ""))),
        "flow_duration": duration_us,
        "total_fwd_packets": packets_sent,
        "total_backward_packets": packets_recv,
        "total_length_of_fwd_packets": bytes_sent,
        "total_length_of_bwd_packets": bytes_recv,
        "fwd_packet_length_max": val("fwd_pkt_len_max", "fwd_packet_length_max"),
        "fwd_packet_length_min": val("fwd_pkt_len_min", "fwd_packet_length_min"),
        "fwd_packet_length_mean": fwd_mean,
        "fwd_packet_length_std": val("fwd_pkt_len_std", "fwd_packet_length_std"),
        "bwd_packet_length_max": val("bwd_pkt_len_max", "bwd_packet_length_max"),
        "bwd_packet_length_min": val("bwd_pkt_len_min", "bwd_packet_length_min"),
        "bwd_packet_length_mean": bwd_mean,
        "bwd_packet_length_std": val("bwd_pkt_len_std", "bwd_packet_length_std"),
        "flow_bytes_per_s": bytes_total / duration_s,
        "flow_packets_per_s": packets_total / duration_s,
        "flow_iat_mean": _safe_float(f.get("iat_mean", 0)) * 1_000_000.0,
        "flow_iat_std": _safe_float(f.get("iat_std", 0)) * 1_000_000.0,
        "flow_iat_max": _safe_float(f.get("iat_max", 0)) * 1_000_000.0,
        "flow_iat_min": val_us("iat_min", "flow_iat_min"),
        "fwd_iat_total": val_us("fwd_iat_total", "fwd_iat_total"),
        "fwd_iat_mean": _safe_float(f.get("fwd_iat_mean", 0)) * 1_000_000.0,
        "fwd_iat_std": val_us("fwd_iat_std", "fwd_iat_std"),
        "fwd_iat_max": val_us("fwd_iat_max", "fwd_iat_max"),
        "fwd_iat_min": val_us("fwd_iat_min", "fwd_iat_min"),
        "bwd_iat_total": val_us("bwd_iat_total", "bwd_iat_total"),
        "bwd_iat_mean": val_us("bwd_iat_mean", "bwd_iat_mean"),
        "bwd_iat_std": val_us("bwd_iat_std", "bwd_iat_std"),
        "bwd_iat_max": val_us("bwd_iat_max", "bwd_iat_max"),
        "bwd_iat_min": val_us("bwd_iat_min", "bwd_iat_min"),
        "fwd_psh_flags": val("fwd_psh_count", "fwd_psh_flags"),
        "bwd_psh_flags": val("bwd_psh_count", "bwd_psh_flags"),
        "fwd_urg_flags": val("fwd_urg_count", "fwd_urg_flags"),
        "bwd_urg_flags": val("bwd_urg_count", "bwd_urg_flags"),
        "fwd_header_length": val("fwd_header_len", "fwd_header_length"),
        "bwd_header_length": val("bwd_header_len", "bwd_header_length"),
        "fwd_packets_per_s": packets_sent / duration_s,
        "bwd_packets_per_s": packets_recv / duration_s,
        "min_packet_length": val("pkt_len_min", "min_packet_length"),
        "max_packet_length": val("pkt_len_max", "max_packet_length"),
        "packet_length_mean": pkt_mean,
        "packet_length_std": val("pkt_len_std", "packet_length_std"),
        "packet_length_variance": (
            _safe_float(pkt_len_std) ** 2
            if pkt_len_std is not None
            else _fill_value(fill, "packet_length_variance")
        ),
        "fin_flag_count": val("fin_count", "fin_flag_count"),
        "syn_flag_count": val("syn_count", "syn_flag_count"),
        "rst_flag_count": val("rst_count", "rst_flag_count"),
        "psh_flag_count": val("psh_count", "psh_flag_count"),
        "ack_flag_count": val("ack_count", "ack_flag_count"),
        "urg_flag_count": val("urg_count", "urg_flag_count"),
        "cwe_flag_count": _fill_value(fill, "cwe_flag_count"),
        "ece_flag_count": val("ece_count", "ece_flag_count"),
        "down_up_ratio": packets_recv / max(packets_sent, 1),
        "average_packet_size": pkt_mean,
        "avg_fwd_segment_size": fwd_mean,
        "avg_bwd_segment_size": bwd_mean,
        "fwd_avg_bytes_per_bulk": _fill_value(fill, "fwd_avg_bytes_per_bulk"),
        "fwd_avg_packets_per_bulk": _fill_value(fill, "fwd_avg_packets_per_bulk"),
        "fwd_avg_bulk_rate": _fill_value(fill, "fwd_avg_bulk_rate"),
        "bwd_avg_bytes_per_bulk": _fill_value(fill, "bwd_avg_bytes_per_bulk"),
        "bwd_avg_packets_per_bulk": _fill_value(fill, "bwd_avg_packets_per_bulk"),
        "bwd_avg_bulk_rate": _fill_value(fill, "bwd_avg_bulk_rate"),
        "subflow_fwd_packets": packets_sent,
        "subflow_fwd_bytes": bytes_sent,
        "subflow_bwd_packets": packets_recv,
        "subflow_bwd_bytes": bytes_recv,
        "init_win_bytes_forward": val("init_win_fwd", "init_win_bytes_forward"),
        "init_win_bytes_backward": val("init_win_bwd", "init_win_bytes_backward"),
        "act_data_pkt_fwd": val("act_data_pkt_fwd", "act_data_pkt_fwd"),
        "min_seg_size_forward": val("min_seg_size_fwd", "min_seg_size_forward"),
        "active_mean": _fill_value(fill, "active_mean"),
        "active_std": _fill_value(fill, "active_std"),
        "active_max": _fill_value(fill, "active_max"),
        "active_min": _fill_value(fill, "active_min"),
        "idle_mean": _fill_value(fill, "idle_mean"),
        "idle_std": _fill_value(fill, "idle_std"),
        "idle_max": _fill_value(fill, "idle_max"),
        "idle_min": _fill_value(fill, "idle_min"),
    }


def build_full_feature_matrix(flows: list, fill_values: dict | None = None) -> pd.DataFrame:
    """packetEye flow dicts → full-feature matrix for schema v4 models.

    Live/offline producers cannot measure every CIC dimension (bulk rates,
    active/idle windows); those come from fill_values — the per-feature
    training medians saved by train_baseline.py --feature-set full.
    """
    if not flows:
        return pd.DataFrame(columns=["flow_id"] + CIC_FULL_FEATURE_NAMES)
    fill = fill_values or {}
    rows = [
        _full_row_from_flow(f if isinstance(f, dict) else f.to_dict(), fill)
        for f in flows
    ]
    return pd.DataFrame(rows)


def feature_names_for(feature_set: str) -> list[str]:
    return CIC_FULL_FEATURE_NAMES if feature_set == "full" else FEATURE_NAMES


def feature_set_of(names: list[str]) -> str:
    """Classify a saved schema's names as legacy (v3) or full (v4)."""
    if not names:
        raise ValueError("Feature schema is empty")
    if all(n in FEATURE_NAMES for n in names):
        return "legacy"
    if all(n in CIC_FULL_FEATURE_NAMES for n in names):
        return "full"
    unknown = [n for n in names if n not in FEATURE_NAMES and n not in CIC_FULL_FEATURE_NAMES]
    raise ValueError(
        f"Feature schema mismatch: schema names {unknown} are not produced "
        "by any current feature builder"
    )


def validate_feature_schema(loaded_names: list[str], expected: list[str] | None = None) -> None:
    """A saved schema is valid if every feature it names can still be produced.

    Older models trained on a subset of a feature set stay usable: inference
    selects exactly the columns the model was trained on. With no explicit
    `expected`, the schema may belong to either the legacy or the full set.
    """
    if expected is None:
        feature_set_of(loaded_names)  # raises on unknown names
        return
    if not loaded_names:
        raise ValueError("Feature schema is empty")
    unknown = [n for n in loaded_names if n not in expected]
    if unknown:
        raise ValueError(
            f"Feature schema mismatch: schema names {unknown} are not produced "
            f"by the current feature builder ({expected})"
        )


def save_feature_schema(path: Path, feature_set: str = "legacy") -> None:
    names = feature_names_for(feature_set)
    version = FULL_FEATURE_SCHEMA_VERSION if feature_set == "full" else FEATURE_SCHEMA_VERSION
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {"feature_names": names, "version": version, "feature_set": feature_set},
            f,
            indent=2,
        )


def load_feature_schema_info(path: Path) -> dict:
    """Schema names plus which feature set (and builder) they belong to."""
    if not path.exists():
        return {
            "feature_names": list(FEATURE_NAMES),
            "feature_set": "legacy",
            "version": FEATURE_SCHEMA_VERSION,
        }
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    names = data.get("feature_names", FEATURE_NAMES)
    feature_set = feature_set_of(names)  # trust names over any stored label
    return {
        "feature_names": names,
        "feature_set": feature_set,
        "version": data.get(
            "version",
            FULL_FEATURE_SCHEMA_VERSION if feature_set == "full" else FEATURE_SCHEMA_VERSION,
        ),
    }


def load_feature_schema(path: Path) -> list[str]:
    return load_feature_schema_info(path)["feature_names"]


def save_feature_fill_values(values: dict, path: Path) -> None:
    """Per-feature training medians for features live capture cannot derive."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, indent=2), encoding="utf-8")


def load_feature_fill_values(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not load feature fill values from %s: %s", path, exc)
        return {}
