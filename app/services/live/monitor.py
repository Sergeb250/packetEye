"""Live NIDS monitor — scores Suricata flows with the baseline ML model."""

import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.services.detection.ml_engine import MLEngine
from app.services.live.alert_service import AlertService
from app.services.live.correlation import LiveCorrelator
from app.services.live.suricata_consumer import SuricataConsumer
from app.services.live.scapy_flow_monitor import ScapyFlowMonitor
from app.services.detection.engine import WhitelistEngine
from app.services.live.webhook_notifier import get_webhook_notifier
from app.services.streams import get_session_store

logger = logging.getLogger(__name__)

_active_monitors: dict[str, threading.Thread] = {}
_monitor_instances: dict[str, "LiveMonitor"] = {}
_stop_flags: dict[str, threading.Event] = {}


class LiveMonitor:
    def __init__(self, config: dict, session_id: str):
        self.config = config
        self.session_id = session_id
        store = get_session_store()
        analysis = store.get(session_id) if store else None
        summary = (analysis.get("summary_json") or {}) if analysis else {}
        source = summary.get("capture_source") or summary.get("source_mode") or "suricata"
        self.source = source
        self.lab_mode = bool(config.get("CAPTURE_LAB_ENABLED"))

        if source == "scapy":
            idle = float(config.get("SCAPY_FLOW_IDLE_SEC", 5))
            self.consumer = None
            self.scapy_monitor = ScapyFlowMonitor(idle_seconds=idle)
        else:
            eve_path = summary.get("eve_path") or config.get("SURICATA_EVE_PATH", "")
            self.consumer = SuricataConsumer(
                eve_path,
                entropy_window=int(config.get("LIVE_PORT_ENTROPY_WINDOW", 300)),
            )
            self.scapy_monitor = None
        ml_threshold = float(config.get("ML_ANOMALY_THRESHOLD", 5.0))
        if self.lab_mode:
            ml_threshold = float(config.get("LIVE_ML_LAB_THRESHOLD", 4.0))
        self.ml = MLEngine(
            model_path=Path(config.get("ML_MODEL_PATH", "")),
            scaler_path=Path(config.get("ML_SCALER_PATH", "")),
            schema_path=Path(config.get("ML_FEATURE_SCHEMA_PATH", "")),
            calibration_path=Path(config.get("ML_SCORE_CALIBRATION_PATH", "")) if config.get("ML_SCORE_CALIBRATION_PATH") else None,
            threshold=ml_threshold,
            max_flows=int(config.get("MAX_FLOWS_ML_SCORING", 50000)),
            train_on_pcap_fallback=config.get("ML_TRAIN_ON_PCAP_FALLBACK", False),
        )
        webhook = get_webhook_notifier(config)
        whitelist = None if self.lab_mode else WhitelistEngine(Path(config.get("WHITELIST_PATH", "")))
        self.alerts = AlertService(
            session_id,
            rate_limit_per_minute=int(config.get("LIVE_ALERT_RATE_LIMIT", 60)),
            threshold=ml_threshold,
            webhook=webhook,
            whitelist=whitelist,
            ml_strict_c2_filter=not self.lab_mode,
        )
        self.correlator = LiveCorrelator(
            window_seconds=int(config.get("LIVE_CORRELATION_WINDOW", 120))
        )
        self.ingest_suricata_alerts = bool(config.get("LIVE_INGEST_SURICATA_ALERTS", True))
        self.auto_investigate = bool(config.get("AUTO_INVESTIGATE_LIVE", False))
        self._flows_processed = 0
        self._alerts_count = 0

    def _post_alert(self, alert: dict | None) -> None:
        if not alert:
            return
        self._alerts_count += 1
        try:
            from app.services.live.triage_registry import register_from_alert

            register_from_alert(self.session_id, alert)
        except Exception as exc:
            logger.debug("Triage registry skip: %s", exc)

    def process_batch(self) -> int:
        if self.scapy_monitor:
            events = self.scapy_monitor.poll_events()
        else:
            events = self.consumer.poll_events()
        flows = events["flows"]

        if self.ingest_suricata_alerts:
            for suricata_alert in events["alerts"]:
                self._post_alert(self.alerts.emit_suricata(suricata_alert))
                for match in self.correlator.add_suricata(suricata_alert):
                    self._post_alert(self.alerts.emit_correlation(match))

        if not flows:
            if events["alerts"]:
                self._update_session_stats()
            return 0

        for f in flows:
            f["id"] = str(uuid.uuid4())

        results = self.ml.score_flows(flows)
        for f, result in zip(flows, results):
            self._post_alert(self.alerts.emit(f, result))
            for match in self.correlator.add_ml(f, result):
                self._post_alert(self.alerts.emit_correlation(match))

        self._flows_processed += len(flows)
        self._update_session_stats()

        return len(flows)

    def _update_session_stats(self) -> None:
        store = get_session_store()
        if not store:
            return
        record = store.get(self.session_id)
        if record:
            progress = min(99, int(record.get("progress_pct") or 0) + 1)
            store.update(
                self.session_id,
                {
                    "total_flows": self._flows_processed,
                    "total_findings": self._alerts_count,
                    "progress_pct": progress,
                    "status": "analyzing",
                },
            )

    def run_loop(self, stop_event: threading.Event, poll_interval: float = 2.0):
        logger.info("Live monitor started for session %s", self.session_id)
        while not stop_event.is_set():
            try:
                self.process_batch()
            except Exception as exc:
                logger.exception("Live monitor batch error: %s", exc)
            stop_event.wait(poll_interval)

        store = get_session_store()
        if store:
            store.update(
                self.session_id,
                {
                    "status": "complete",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "progress_pct": 100,
                },
            )
        logger.info("Live monitor stopped for session %s", self.session_id)


def start_monitor(app, session_id: str) -> bool:
    if session_id in _active_monitors and _active_monitors[session_id].is_alive():
        return False

    stop_event = threading.Event()
    _stop_flags[session_id] = stop_event

    def _target():
        with app.app_context():
            monitor = LiveMonitor(dict(app.config), session_id)
            _monitor_instances[session_id] = monitor
            try:
                monitor.run_loop(stop_event)
            finally:
                _monitor_instances.pop(session_id, None)

    thread = threading.Thread(target=_target, daemon=True, name=f"live-{session_id[:8]}")
    _active_monitors[session_id] = thread
    thread.start()
    return True


def stop_monitor(session_id: str) -> bool:
    stop_event = _stop_flags.get(session_id)
    if not stop_event:
        return False
    stop_event.set()
    thread = _active_monitors.get(session_id)
    if thread:
        thread.join(timeout=10)
    _active_monitors.pop(session_id, None)
    _stop_flags.pop(session_id, None)
    return True


def rebind_eve(session_id: str, eve_path: str) -> bool:
    """Point a running live session at a new EVE file without restarting Suricata."""
    store = get_session_store()
    if not store or not store.get(session_id):
        return False
    record = store.get(session_id)
    summary = dict((record or {}).get("summary_json") or {})
    summary["eve_path"] = eve_path
    store.update(session_id, {"summary_json": summary})
    mon = _monitor_instances.get(session_id)
    if mon and mon.consumer:
        mon.consumer.rebind(eve_path)
    return True


def monitor_status(session_id: str) -> dict:
    thread = _active_monitors.get(session_id)
    running = thread is not None and thread.is_alive()
    store = get_session_store()
    analysis = store.get(session_id) if store else None
    return {
        "session_id": session_id,
        "running": running,
        "status": analysis.get("status", "unknown") if analysis else "unknown",
        "total_flows": analysis.get("total_flows", 0) if analysis else 0,
        "total_findings": analysis.get("total_findings", 0) if analysis else 0,
        "progress_pct": analysis.get("progress_pct", 0) if analysis else 0,
    }
