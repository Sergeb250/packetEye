"""Attach/stop ML live sessions alongside dashboard capture."""

from __future__ import annotations

import logging
from pathlib import Path

from app.services.capture import orchestrator as capture_orchestrator
from app.services.live.monitor import monitor_status, stop_monitor
from app.services.live_runner import kickoff_live_monitor_current
from app.services.streams import get_session_store
from app.tasks.live_tasks import create_live_session, stop_live_monitor_task

logger = logging.getLogger(__name__)


def _resolve_eve_path(config: dict, eve_hint: str | None = None) -> str:
    raw = (eve_hint or "").strip() or str(config.get("SURICATA_EVE_PATH") or "").strip()
    if not raw:
        log_dir = str(config.get("SURICATA_LOG_DIR") or "").strip()
        if log_dir:
            raw = str(Path(log_dir) / "eve.json")
    return str(Path(raw).expanduser().resolve()) if raw else ""


def attach_ml_to_capture(
    config: dict,
    mode: str,
    interface: str,
    eve_hint: str | None = None,
) -> dict:
    """Start (or reuse) a live ML session for the current capture mode."""
    mode = (mode or "suricata").strip().lower()
    iface = (interface or "").strip() or str(config.get("CAPTURE_INTERFACE") or "eth0")

    existing = capture_orchestrator.get_ml_session_id(config)
    if existing:
        status = monitor_status(existing)
        if status.get("running"):
            return {"session_id": existing, "status": "already_running", "mode": mode}

    model_path = Path(config.get("ML_MODEL_PATH", ""))
    if not model_path.is_file():
        return {"session_id": None, "status": "model_missing", "mode": mode}

    if mode == "tcpdump":
        if not config.get("LIVE_ML_TCPDUMP_ENABLED", True):
            return {"session_id": None, "status": "disabled", "mode": mode}
        session = create_live_session(config, interface=iface, capture_source="scapy")
    else:
        eve_path = _resolve_eve_path(config, eve_hint)
        if not eve_path:
            return {"session_id": None, "status": "no_eve", "mode": mode}
        session = create_live_session(
            config, eve_path=eve_path, interface=iface, capture_source="suricata"
        )

    session_id = session["id"]
    kickoff_live_monitor_current(session_id)
    capture_orchestrator.set_ml_session_id(config, session_id)
    logger.info("ML live session attached: %s mode=%s iface=%s", session_id, mode, iface)
    return {"session_id": session_id, "status": "running", "mode": mode}


def stop_ml_for_capture(config: dict) -> dict:
    """Stop ML session linked to capture (or any running live session)."""
    session_id = capture_orchestrator.get_ml_session_id(config)
    if not session_id:
        store = get_session_store()
        running = store.find_running() if store else None
        if running and monitor_status(running["id"]).get("running"):
            session_id = running["id"]

    if not session_id:
        return {"ok": True, "stopped": False}

    stop_monitor(session_id)
    stop_live_monitor_task.delay(session_id)
    store = get_session_store()
    if store:
        record = store.get(session_id)
        if record and record.get("status") == "analyzing":
            store.update(session_id, {"status": "complete"})
    capture_orchestrator.set_ml_session_id(config, None)
    logger.info("ML live session stopped: %s", session_id)
    return {"ok": True, "stopped": True, "session_id": session_id}
