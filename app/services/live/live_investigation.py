"""Live-path OSINT and alert investigation (no SQLAlchemy Analysis/Finding)."""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone

from app.services.investigation.service import InvestigationService, MAX_TARGETS_PER_INVESTIGATION
from app.services.investigation.service import _is_ip, _is_public_ip, _looks_like_domain
from app.services.investigation.service import investigate_target_sync
from app.services.live.alert_service import AlertService
from app.services.streams import get_alert_writer

logger = logging.getLogger(__name__)


def get_live_alert(session_id: str, alert_id: str) -> dict | None:
    for alert in AlertService.get_alerts(session_id, since_ts=0):
        if alert.get("id") == alert_id or alert.get("finding_id") == alert_id:
            return alert
    return None


def extract_targets_from_alert(alert: dict) -> list[dict]:
    targets: list[dict] = []
    seen: set[str] = set()

    def add(kind: str, value) -> None:
        v = str(value or "").strip()
        if not v or v in seen or len(targets) >= MAX_TARGETS_PER_INVESTIGATION:
            return
        if kind == "ip" and not _is_ip(v):
            return
        if kind == "domain" and not _looks_like_domain(v):
            return
        seen.add(v)
        targets.append({"type": kind, "value": v, "public": _is_public_ip(v) if kind == "ip" else True})

    for key in ("src_ip", "dst_ip", "dest_ip", "ip"):
        add("ip", alert.get(key))
    for key in ("domain", "hostname", "tls_sni", "dns_query"):
        add("domain", alert.get(key))
    enhanced = alert.get("enhanced") or {}
    osint = enhanced.get("osint") or {}
    if isinstance(osint, dict):
        for key in ("domain", "hostname"):
            add("domain", osint.get(key))
    return targets


def live_osint_target(
    config: dict,
    session_id: str,
    target: str,
    *,
    summarize: bool = True,
    alert_context: dict | None = None,
    detail_level: str = "medium",
) -> dict:
    target = target.strip()
    target_type = "domain"
    try:
        ipaddress.ip_address(target)
        target_type = "ip"
    except ValueError:
        if "." not in target:
            return {"ok": False, "error": "Invalid target"}
    return investigate_target_sync(
        config,
        session_id,
        target_type,
        target,
        summarize=summarize,
        alert_context=alert_context,
        detail_level=detail_level,
    )


def get_live_alert_investigation(session_id: str, alert_id: str) -> dict:
    alert = get_live_alert(session_id, alert_id)
    if not alert:
        return {"ok": False, "error": "Alert not found"}
    inv = alert.get("investigation") or {"status": "none"}
    return {
        "ok": True,
        "alert_id": alert_id,
        "session_id": session_id,
        "investigation": inv,
    }


def investigate_live_alert_sync(config: dict, session_id: str, alert_id: str) -> dict:
    alert = get_live_alert(session_id, alert_id)
    if not alert:
        return {"ok": False, "error": "Alert not found"}

    targets = extract_targets_from_alert(alert)
    if not targets:
        result = {
            "status": "complete",
            "at": datetime.now(timezone.utc).isoformat(),
            "targets": {},
            "note": "No public IPs or domains found in this alert.",
        }
        _patch_alert_investigation(session_id, alert_id, result)
        return {"ok": True, "investigation": result}

    running = {
        "status": "running",
        "at": datetime.now(timezone.utc).isoformat(),
        "targets": {},
    }
    _patch_alert_investigation(session_id, alert_id, running)

    try:
        service = InvestigationService(config)
        results = service.run(targets)
    except Exception as exc:
        logger.exception("Live alert investigation failed %s/%s", session_id, alert_id)
        result = {
            "status": "failed",
            "at": datetime.now(timezone.utc).isoformat(),
            "error": str(exc),
        }
        _patch_alert_investigation(session_id, alert_id, result)
        return {"ok": False, "error": str(exc), "investigation": result}

    malicious = [v for v in results.values() if v.get("is_malicious")]
    result = {
        "status": "complete",
        "at": datetime.now(timezone.utc).isoformat(),
        "targets": results,
        "malicious_count": len(malicious),
    }
    _patch_alert_investigation(session_id, alert_id, result)
    return {"ok": True, "investigation": result}


def _patch_alert_investigation(session_id: str, alert_id: str, investigation: dict) -> None:
    writer = get_alert_writer()
    if writer:
        writer.update(session_id, alert_id, {"investigation": investigation})
