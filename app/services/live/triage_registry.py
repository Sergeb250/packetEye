"""Unified live triage incident registry — Suricata, ML, LLM, heuristics, correlation."""

from __future__ import annotations

import time
import uuid

from app.services.streams import get_incident_tracker

DISPOSITIONS = frozenset({
    "open", "true_positive", "false_positive", "true_negative", "benign", "error",
})

SOURCE_MAP = {
    "suricata": "suricata",
    "ml": "ml",
    "llm": "llm",
    "correlation": "correlation",
    "suricata_ml_correlation": "correlation",
    "heuristic": "heuristic",
}


def _tracker():
    return get_incident_tracker()


def _load(session_id: str) -> list[dict]:
    tracker = _tracker()
    if not tracker:
        return []
    return tracker.load(session_id)


def _save(session_id: str, rows: list[dict]) -> None:
    tracker = _tracker()
    if tracker:
        tracker.save(session_id, rows)


def _connection_key(row: dict) -> str:
    return "|".join(
        str(row.get(k) or "")
        for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
    )


def _normalize_sources(sources: list[str] | str | None) -> list[str]:
    if not sources:
        return []
    if isinstance(sources, str):
        sources = [sources]
    out: list[str] = []
    for s in sources:
        mapped = SOURCE_MAP.get(str(s).lower(), str(s).lower())
        if mapped and mapped not in out:
            out.append(mapped)
    return out


def build_incident_row(
    *,
    session_id: str,
    src_ip: str = "",
    dst_ip: str = "",
    src_port: int = 0,
    dst_port: int = 0,
    protocol: str = "TCP",
    sources: list[str] | str | None = None,
    attack_type: str = "Unknown",
    severity: str = "info",
    confidence: float = 0.0,
    disposition: str = "open",
    ai_status: str = "",
    llm_primary: dict | None = None,
    llm_secondary: dict | None = None,
    llm_tertiary: dict | None = None,
    llm_merged_summary: str = "",
    verdict_line: str = "",
    errors: list[str] | None = None,
    alert_id: str | None = None,
    finding_id: str | None = None,
    packet: dict | None = None,
    indicators: list[str] | None = None,
    deep_inspect: dict | None = None,
    timestamp: float | None = None,
) -> dict:
    disp = disposition if disposition in DISPOSITIONS else "open"
    status = (ai_status or disp).lower()
    if status not in DISPOSITIONS:
        status = disp
    return {
        "id": str(uuid.uuid4()),
        "timestamp": timestamp or time.time(),
        "session_id": session_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port or 0),
        "dst_port": int(dst_port or 0),
        "protocol": protocol or "TCP",
        "sources": _normalize_sources(sources),
        "attack_type": attack_type,
        "severity": severity,
        "confidence": round(float(confidence or 0), 3),
        "disposition": disp,
        "ai_status": status,
        "llm_primary": llm_primary or {},
        "llm_secondary": llm_secondary or {},
        "llm_tertiary": llm_tertiary or {},
        "llm_merged_summary": llm_merged_summary or "",
        "verdict_line": verdict_line or "",
        "errors": list(errors or []),
        "alert_ids": [alert_id] if alert_id else [],
        "finding_id": finding_id,
        "packet": packet or {},
        "indicators": list(indicators or []),
        "deep_inspect": deep_inspect or {},
        "analyst_note": "",
    }


def upsert_incident(session_id: str, row: dict) -> dict:
    """Insert or merge into existing row with same connection (any disposition)."""
    rows = _load(session_id)
    key = _connection_key(row)
    if not key.strip("|"):
        rows.append(row)
        _save(session_id, rows)
        return row
    merged = None
    for i, existing in enumerate(rows):
        if _connection_key(existing) != key:
            continue
        merged = dict(existing)
        for src in row.get("sources") or []:
            if src not in merged.get("sources", []):
                merged.setdefault("sources", []).append(src)
        merged["severity"] = _max_severity(merged.get("severity"), row.get("severity"))
        merged["confidence"] = max(float(merged.get("confidence") or 0), float(row.get("confidence") or 0))
        if row.get("llm_merged_summary"):
            merged["llm_merged_summary"] = row["llm_merged_summary"]
        if row.get("llm_primary"):
            merged["llm_primary"] = row["llm_primary"]
        if row.get("llm_secondary"):
            merged["llm_secondary"] = row["llm_secondary"]
        if row.get("llm_tertiary"):
            merged["llm_tertiary"] = row["llm_tertiary"]
        if row.get("attack_type") and row["attack_type"] != "Unknown":
            merged["attack_type"] = row["attack_type"]
        for e in row.get("errors") or []:
            if e not in merged.get("errors", []):
                merged.setdefault("errors", []).append(e)
        if row.get("finding_id"):
            merged["finding_id"] = row["finding_id"]
        if row.get("alert_ids"):
            merged.setdefault("alert_ids", []).extend(
                aid for aid in row["alert_ids"] if aid not in merged.get("alert_ids", [])
            )
        if row.get("packet"):
            merged["packet"] = row["packet"]
        if row.get("indicators"):
            merged["indicators"] = list(set((merged.get("indicators") or []) + row["indicators"]))
        merged["from_ai"] = "llm" in (merged.get("sources") or []) or bool(merged.get("llm_primary"))
        rows[i] = merged
        _save(session_id, rows)
        return merged

    sources = row.get("sources") or []
    row["from_ai"] = "llm" in sources or bool(row.get("llm_primary"))
    rows.append(row)
    _save(session_id, rows)
    return row


def register_from_alert(session_id: str, alert: dict) -> dict:
    """Create/update registry row from a live alert feed item."""
    atype = alert.get("type") or "ml"
    source = SOURCE_MAP.get(str(atype).lower(), str(atype).lower())
    attack = alert.get("attack_type") or alert.get("signature") or alert.get("explanation") or "Alert"
    if source == "ml":
        attack = f"ML anomaly ({alert.get('anomaly_score', '?')})"
    if source == "llm":
        attack = alert.get("attack_type") or attack
    sources = [source]
    if source == "llm" and "heuristic" in str(alert.get("models") or ""):
        sources.append("heuristic")
    row = build_incident_row(
        session_id=session_id,
        src_ip=alert.get("src_ip") or "",
        dst_ip=alert.get("dst_ip") or "",
        src_port=alert.get("src_port") or 0,
        dst_port=alert.get("dst_port") or 0,
        protocol=alert.get("protocol") or "TCP",
        sources=sources,
        attack_type=str(attack)[:120],
        severity=alert.get("severity") or "medium",
        confidence=float(alert.get("confidence") or alert.get("anomaly_score") or 0) / 10.0
        if alert.get("anomaly_score") and not alert.get("confidence")
        else float(alert.get("confidence") or 0.5),
        disposition="true_positive" if source == "llm" else "open",
        llm_merged_summary=(alert.get("explanation") or "")[:500],
        llm_primary=alert.get("llm_primary") or {},
        llm_secondary=alert.get("llm_secondary") or {},
        llm_tertiary=alert.get("llm_tertiary") or {},
        alert_id=alert.get("id"),
        finding_id=alert.get("finding_id"),
        timestamp=alert.get("timestamp") or time.time(),
    )
    row["from_ai"] = source == "llm" or bool(alert.get("from_ai"))
    return upsert_incident(session_id, row)


def list_incidents(
    session_id: str,
    *,
    since_ts: float = 0,
    disposition: str | None = None,
    source: str | None = None,
    search: str | None = None,
    limit: int = 200,
) -> list[dict]:
    rows = _load(session_id)
    out: list[dict] = []
    q = (search or "").strip().lower()
    for row in reversed(rows):
        if since_ts and float(row.get("timestamp") or 0) <= since_ts:
            continue
        if disposition and row.get("disposition") != disposition:
            continue
        if source and source not in (row.get("sources") or []):
            continue
        if q:
            hay = " ".join(
                str(row.get(k) or "")
                for k in (
                    "src_ip", "dst_ip", "attack_type", "llm_merged_summary",
                    "protocol", "disposition",
                )
            ).lower()
            if q not in hay:
                continue
        out.append(row)
        if len(out) >= limit:
            break
    return out


def get_incident(session_id: str, incident_id: str) -> dict | None:
    for row in _load(session_id):
        if row.get("id") == incident_id:
            return row
    return None


def update_incident(session_id: str, incident_id: str, patch: dict) -> dict | None:
    rows = _load(session_id)
    for i, row in enumerate(rows):
        if row.get("id") != incident_id:
            continue
        updated = dict(row)
        updated.update({k: v for k, v in patch.items() if v is not None})
        rows[i] = updated
        _save(session_id, rows)
        return updated
    return None


def set_verdict(
    session_id: str,
    incident_id: str,
    disposition: str,
    *,
    analyst_note: str = "",
) -> dict | None:
    if disposition not in DISPOSITIONS:
        disposition = "open"
    return update_incident(
        session_id,
        incident_id,
        {"disposition": disposition, "analyst_note": analyst_note},
    )


def summary_stats(session_id: str) -> dict:
    rows = _load(session_id)
    counts: dict[str, int] = {d: 0 for d in DISPOSITIONS}
    source_counts: dict[str, int] = {}
    for row in rows:
        disp = row.get("disposition") or "open"
        counts[disp] = counts.get(disp, 0) + 1
        for src in row.get("sources") or []:
            source_counts[src] = source_counts.get(src, 0) + 1
    return {
        "total": len(rows),
        "by_disposition": counts,
        "by_source": source_counts,
    }


def _max_severity(a: str | None, b: str | None) -> str:
    rank = {"info": 0, "medium": 1, "high": 2, "critical": 3}
    sa = rank.get(str(a or "info").lower(), 0)
    sb = rank.get(str(b or "info").lower(), 0)
    inv = {v: k for k, v in rank.items()}
    return inv[max(sa, sb)]
