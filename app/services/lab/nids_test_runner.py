"""Long-running NIDS + ML soak test — capture, lab traffic, alert monitoring."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from pathlib import Path

from flask import Flask

from app.config import BASE_DIR
from app.services.capture import ml_capture, orchestrator as capture_orchestrator
from app.services.capture import pcap_watcher
from app.services.lab import traffic_runner
from app.services.lab.patterns import ALL_LAB_PATTERNS, PATTERN_CIC_LABELS
from app.services.live import packet_feed
from app.services.live.alert_service import AlertService
from app.services.live.monitor import monitor_status

logger = logging.getLogger(__name__)


def _init_coverage() -> dict[str, dict]:
    return {
        p: {
            "pattern": p,
            "cic_label": PATTERN_CIC_LABELS.get(p, p),
            "alerted_ml": False,
            "alerted_suricata": False,
            "completed": False,
        }
        for p in ALL_LAB_PATTERNS
    }


def _coverage_rows(coverage: dict[str, dict]) -> list[dict]:
    order = {p: i for i, p in enumerate(ALL_LAB_PATTERNS)}
    return sorted(coverage.values(), key=lambda r: order.get(r["pattern"], 999))


def update_pattern_coverage(
    coverage: dict[str, dict],
    window: dict | None,
    *,
    session_id: str,
    started_at: float,
    current_pattern: str | None,
    prev_pattern: str | None,
    alert_ml: int,
    alert_suri: int,
) -> tuple[dict | None, dict[str, dict]]:
    """Update coverage map when lab patterns rotate; returns (new_window, coverage)."""

    def _apply_window_delta(pattern: str, w: dict) -> None:
        rec = coverage.get(pattern)
        if not rec:
            return
        if alert_ml > w.get("ml_at_start", 0):
            rec["alerted_ml"] = True
        if alert_suri > w.get("suri_at_start", 0):
            rec["alerted_suricata"] = True

    if prev_pattern and prev_pattern != current_pattern and window and window.get("pattern") == prev_pattern:
        _apply_window_delta(prev_pattern, window)
        rec = coverage.get(prev_pattern)
        if rec:
            rec["completed"] = True

    if current_pattern and current_pattern != prev_pattern:
        window = {
            "pattern": current_pattern,
            "ml_at_start": alert_ml,
            "suri_at_start": alert_suri,
            "started_at": time.time(),
        }
        if current_pattern not in coverage:
            coverage[current_pattern] = {
                "pattern": current_pattern,
                "cic_label": PATTERN_CIC_LABELS.get(current_pattern, current_pattern),
                "alerted_ml": False,
                "alerted_suricata": False,
                "completed": False,
            }

    if current_pattern and window and window.get("pattern") == current_pattern:
        _apply_window_delta(current_pattern, window)

    return window, coverage


_state: dict = {
    "running": False,
    "stop_event": None,
    "thread": None,
    "app": None,
    "session_id": None,
    "mode": "",
    "interface": "",
    "with_lab": False,
    "lab_started_by_test": False,
    "stop_live_on_exit": True,
    "started_at": None,
    "log": deque(maxlen=500),
    "stats": {},
    "last_error": None,
    "pattern_coverage": {},
    "coverage_window": None,
    "last_pattern": None,
}


def _log(line: str) -> None:
    text = (line or "").rstrip()
    if text:
        _state["log"].append(text)
        logger.info("[nids-test] %s", text)


def _count_alerts(session_id: str, since_ts: float) -> dict:
    alerts = AlertService.get_alerts(session_id, since_ts=since_ts)
    ml = sum(1 for a in alerts if (a.get("type") or "").lower() == "ml")
    suri = sum(1 for a in alerts if (a.get("type") or "").lower() == "suricata")
    by_sev: dict[str, int] = {}
    for a in alerts:
        sev = (a.get("severity") or "unknown").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return {
        "total": len(alerts),
        "ml": ml,
        "suricata": suri,
        "by_severity": by_sev,
        "recent": alerts[-8:],
    }


def _ensure_live_stack(
    app: Flask,
    config: dict,
    *,
    mode: str,
    interface: str | None,
    eve_path: str | None,
    auto_capture: bool,
) -> dict:
    mode = (mode or config.get("CAPTURE_MODE") or "suricata").strip().lower()
    iface = (interface or "").strip() or str(config.get("CAPTURE_INTERFACE") or config.get("SURICATA_INTERFACE") or "eth0")

    if mode == "tcpdump":
        cap = capture_orchestrator.capture_status(config)
        if not cap.get("running"):
            result = capture_orchestrator.start_capture(config, mode="tcpdump", interface=iface)
            if not result.get("ok"):
                return {"ok": False, "error": result.get("error"), "hint": result.get("hint")}
            if result.get("chunk_dir"):
                config["TCPDUMP_CHUNK_DIR"] = result["chunk_dir"]
        pcap_watcher.start_watcher(app)
        packet_feed.start_feed(config, "tcpdump", iface)
        ml = ml_capture.attach_ml_to_capture(config, "tcpdump", iface)
        if not ml.get("session_id"):
            return {"ok": False, "error": f"ML attach failed: {ml.get('status')}"}
        return {"ok": True, "session_id": ml["session_id"], "mode": "tcpdump", "interface": iface}

    eve_hint = eve_path
    if auto_capture:
        cap = capture_orchestrator.capture_status(config)
        if not cap.get("running"):
            result = capture_orchestrator.start_capture(config, mode="suricata", interface=interface)
            if not result.get("ok"):
                return {"ok": False, "error": result.get("error"), "hint": result.get("hint")}
            if result.get("eve_hint"):
                eve_hint = result["eve_hint"]
        elif cap.get("suricata", {}).get("eve", {}).get("path"):
            eve_hint = cap["suricata"]["eve"]["path"]

    resolved = eve_hint or config.get("SURICATA_EVE_PATH", "")
    if resolved:
        resolved = str(Path(resolved).expanduser().resolve())
    if not resolved:
        log_dir = str(config.get("SURICATA_LOG_DIR") or "").strip()
        if log_dir:
            resolved = str(Path(log_dir) / "eve.json")

    if not auto_capture and resolved and not Path(resolved).is_file():
        cap = capture_orchestrator.capture_status(config)
        if not cap.get("running"):
            return {
                "ok": False,
                "error": f"EVE log not found: {resolved}",
                "hint": "Start Suricata capture first or pass eve_path / set SURICATA_EVE_PATH",
            }

    ml = ml_capture.attach_ml_to_capture(config, "suricata", iface, eve_hint=resolved)
    if not ml.get("session_id"):
        return {"ok": False, "error": f"ML attach failed: {ml.get('status')}"}
    return {
        "ok": True,
        "session_id": ml["session_id"],
        "mode": "suricata",
        "interface": iface,
        "eve_path": resolved,
    }


def _watch_loop(app: Flask, poll_sec: float) -> None:
    stop_event: threading.Event = _state["stop_event"]
    session_id = _state["session_id"]
    started_at = _state["started_at"] or time.time()
    with app.app_context():
        while not stop_event.is_set():
            try:
                status = monitor_status(session_id)
                alert_stats = _count_alerts(session_id, started_at)
                lab = traffic_runner.lab_status()
                current_pattern = lab.get("current_pattern")
                prev_pattern = _state.get("last_pattern")
                window, coverage = update_pattern_coverage(
                    dict(_state.get("pattern_coverage") or _init_coverage()),
                    _state.get("coverage_window"),
                    session_id=session_id,
                    started_at=started_at,
                    current_pattern=current_pattern,
                    prev_pattern=prev_pattern,
                    alert_ml=alert_stats["ml"],
                    alert_suri=alert_stats["suricata"],
                )
                _state["pattern_coverage"] = coverage
                _state["coverage_window"] = window
                _state["last_pattern"] = current_pattern
                coverage_rows = _coverage_rows(coverage)
                _state["stats"] = {
                    "polls": _state["stats"].get("polls", 0) + 1,
                    "session_id": session_id,
                    "running": status.get("running"),
                    "total_flows": status.get("total_flows", 0),
                    "total_findings": status.get("total_findings", 0),
                    "alerts": alert_stats,
                    "lab_running": lab.get("running"),
                    "current_pattern": current_pattern,
                    "pattern_started_at": lab.get("pattern_started_at"),
                }
                ml_hits = sum(1 for r in coverage_rows if r.get("alerted_ml"))
                suri_hits = sum(1 for r in coverage_rows if r.get("alerted_suricata"))
                _log(
                    f"poll #{_state['stats']['polls']}: flows={status.get('total_flows', 0)} "
                    f"findings={status.get('total_findings', 0)} "
                    f"alerts(ml={alert_stats['ml']}, suricata={alert_stats['suricata']}) "
                    f"coverage(ml={ml_hits}/{len(coverage_rows)}, suri={suri_hits}/{len(coverage_rows)}) "
                    f"active={current_pattern or '-'}"
                )
            except Exception as exc:
                _state["last_error"] = str(exc)
                _log(f"poll error: {exc}")
            stop_event.wait(poll_sec)
    _state["running"] = False
    _log("monitor loop exited")


def start_nids_soak(
    app: Flask,
    config: dict,
    *,
    mode: str | None = None,
    interface: str | None = None,
    eve_path: str | None = None,
    with_lab: bool = True,
    patterns: list[str] | None = None,
    auto_capture: bool | None = None,
    poll_sec: float = 5.0,
    rotate_sec: int | None = None,
    stop_live_on_exit: bool = True,
) -> dict:
    if _state.get("running"):
        return {"ok": False, "error": "NIDS soak test already running. Stop it first."}
    if not config.get("LIVE_MONITOR_ENABLED"):
        return {"ok": False, "error": "Live monitor disabled. Set LIVE_MONITOR_ENABLED=true in .env"}

    mode = (mode or config.get("CAPTURE_MODE") or "suricata").strip().lower()
    if auto_capture is None:
        auto_capture = mode == "suricata"
    rotate = int(rotate_sec or config.get("LAB_ROTATE_SEC") or 12)

    _state["log"].clear()
    _state["last_error"] = None
    _state["stats"] = {"polls": 0}
    _state["pattern_coverage"] = _init_coverage()
    _state["coverage_window"] = None
    _state["last_pattern"] = None
    _log(f"starting soak test mode={mode} with_lab={with_lab} rotate={rotate}s")

    with app.app_context():
        live = _ensure_live_stack(
            app, dict(config),
            mode=mode,
            interface=interface,
            eve_path=eve_path,
            auto_capture=auto_capture,
        )
    if not live.get("ok"):
        return live

    lab_started = False
    pattern_count = len(ALL_LAB_PATTERNS)
    if with_lab:
        if not config.get("CAPTURE_LAB_ENABLED"):
            _log("lab traffic skipped — set CAPTURE_LAB_ENABLED=true for synthetic attacks")
        else:
            script = BASE_DIR / "scripts" / "generate_test_traffic.py"
            pat = patterns if patterns else None
            iface = (interface or "").strip() or str(config.get("CAPTURE_INTERFACE") or "eth0")
            lab = traffic_runner.start_lab_traffic(script, pat, iface, rotate_sec=rotate)
            if lab.get("ok"):
                lab_started = True
                pattern_count = len(lab.get("patterns") or ALL_LAB_PATTERNS)
                _log(f"lab traffic started all patterns ({pattern_count}) iface={iface}")
            else:
                _log(f"lab traffic failed: {lab.get('error')} — continuing monitor-only")

    stop_event = threading.Event()
    started_at = time.time()
    _state.update({
        "running": True,
        "stop_event": stop_event,
        "app": app,
        "session_id": live["session_id"],
        "mode": live.get("mode", mode),
        "interface": live.get("interface", interface or ""),
        "with_lab": with_lab,
        "lab_started_by_test": lab_started,
        "stop_live_on_exit": stop_live_on_exit,
        "started_at": started_at,
    })

    thread = threading.Thread(
        target=_watch_loop,
        args=(app, max(2.0, float(poll_sec))),
        daemon=True,
        name="nids-soak-test",
    )
    _state["thread"] = thread
    thread.start()

    return {
        "ok": True,
        "session_id": live["session_id"],
        "mode": live.get("mode"),
        "interface": live.get("interface"),
        "eve_path": live.get("eve_path"),
        "with_lab": with_lab,
        "lab_started": lab_started,
        "poll_sec": poll_sec,
        "rotate_sec": rotate,
        "pattern_count": pattern_count,
        "patterns": list(ALL_LAB_PATTERNS),
        "message": "NIDS soak test running until stopped (Ctrl+C or /api/nids-test/stop).",
    }


def stop_nids_soak(*, stop_lab: bool = True, stop_live: bool | None = None) -> dict:
    if not _state.get("running") and not _state.get("thread"):
        return {"ok": True, "message": "NIDS soak test was not running."}

    stop_event = _state.get("stop_event")
    if stop_event:
        stop_event.set()

    if stop_lab and _state.get("lab_started_by_test"):
        traffic_runner.stop_lab_traffic()

    do_stop_live = stop_live if stop_live is not None else _state.get("stop_live_on_exit", True)
    app = _state.get("app")
    session_id = _state.get("session_id")
    if do_stop_live and app and session_id:
        with app.app_context():
            ml_capture.stop_ml_for_capture(dict(app.config))

    thread = _state.get("thread")
    if thread and thread.is_alive():
        thread.join(timeout=12)

    _state.update({
        "running": False,
        "stop_event": None,
        "thread": None,
        "lab_started_by_test": False,
    })
    _log("soak test stopped")
    return {
        "ok": True,
        "message": "NIDS soak test stopped.",
        "session_id": session_id,
        "stats": dict(_state.get("stats") or {}),
        "pattern_coverage": _coverage_rows(_state.get("pattern_coverage") or {}),
    }


def nids_soak_status() -> dict:
    running = bool(_state.get("running"))
    thread = _state.get("thread")
    if running and thread and not thread.is_alive():
        running = False
        _state["running"] = False
    elapsed = round(time.time() - _state["started_at"], 1) if _state.get("started_at") else 0
    coverage = _coverage_rows(_state.get("pattern_coverage") or {})
    return {
        "running": running,
        "session_id": _state.get("session_id"),
        "mode": _state.get("mode"),
        "interface": _state.get("interface"),
        "with_lab": _state.get("with_lab"),
        "lab_running": traffic_runner.lab_status().get("running"),
        "lab_status": traffic_runner.lab_status(),
        "started_at": _state.get("started_at"),
        "elapsed_sec": elapsed,
        "stats": dict(_state.get("stats") or {}),
        "pattern_coverage": coverage,
        "last_error": _state.get("last_error"),
        "log": list(_state.get("log") or []),
    }
