"""Live NIDS monitor — scores Suricata flows with the baseline ML model."""

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app

from app.extensions import db
from app.models.analysis import Analysis, Flow
from app.services.detection.ml_engine import MLEngine
from app.services.live.alert_service import AlertService
from app.services.live.correlation import LiveCorrelator
from app.services.live.suricata_consumer import SuricataConsumer
from app.services.live.webhook_notifier import WebhookNotifier

logger = logging.getLogger(__name__)

_active_monitors: dict[str, threading.Thread] = {}
_stop_flags: dict[str, threading.Event] = {}


class LiveMonitor:
    def __init__(self, config: dict, session_id: str):
        self.config = config
        self.session_id = session_id
        analysis = Analysis.query.get(session_id)
        eve_path = (analysis.summary_json or {}).get("eve_path") if analysis else None
        self.consumer = SuricataConsumer(
            eve_path or config.get("SURICATA_EVE_PATH", ""),
            entropy_window=int(config.get("LIVE_PORT_ENTROPY_WINDOW", 300)),
        )
        self.ml = MLEngine(
            model_path=Path(config.get("ML_MODEL_PATH", "")),
            scaler_path=Path(config.get("ML_SCALER_PATH", "")),
            schema_path=Path(config.get("ML_FEATURE_SCHEMA_PATH", "")),
            calibration_path=Path(config.get("ML_SCORE_CALIBRATION_PATH", "")) if config.get("ML_SCORE_CALIBRATION_PATH") else None,
            threshold=float(config.get("ML_ANOMALY_THRESHOLD", 5.0)),
            max_flows=int(config.get("MAX_FLOWS_ML_SCORING", 50000)),
            train_on_pcap_fallback=config.get("ML_TRAIN_ON_PCAP_FALLBACK", False),
        )
        webhook = WebhookNotifier(config)
        self.alerts = AlertService(
            session_id,
            rate_limit_per_minute=int(config.get("LIVE_ALERT_RATE_LIMIT", 60)),
            threshold=float(config.get("ML_ANOMALY_THRESHOLD", 5.0)),
            webhook=webhook if webhook.enabled else None,
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
        if (
            self.auto_investigate
            and alert.get("finding_id")
            and alert.get("severity") in ("high", "critical")
        ):
            from app.services.investigation.service import kickoff_investigation

            kickoff_investigation(current_app._get_current_object(), alert["finding_id"])

    def process_batch(self) -> int:
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

        flow_rows = []
        for f in flows:
            flow_row = Flow(
                analysis_id=self.session_id,
                src_ip=f["src_ip"],
                dst_ip=f["dst_ip"],
                src_port=f.get("src_port", 0),
                dst_port=f.get("dst_port", 0),
                protocol=f.get("protocol", "TCP"),
                start_time=f.get("start_time"),
                end_time=f.get("end_time"),
                duration_ms=f.get("duration_ms", 0),
                bytes_sent=f.get("bytes_sent", 0),
                bytes_recv=f.get("bytes_recv", 0),
                packets_sent=f.get("packets_sent", 0),
                packets_recv=f.get("packets_recv", 0),
                iat_mean=f.get("iat_mean", 0),
                anomaly_score=0,
            )
            db.session.add(flow_row)
            flow_rows.append(flow_row)

        db.session.flush()
        for f, flow_row in zip(flows, flow_rows):
            f["id"] = flow_row.id

        db.session.commit()

        results = self.ml.score_flows(flows)
        rows_by_id = {row.id: row for row in flow_rows}
        for f, result in zip(flows, results):
            flow_row = rows_by_id.get(f["id"])
            if flow_row:
                flow_row.anomaly_score = result.get("anomaly_score", 0)
            self._post_alert(self.alerts.emit(f, result))
            for match in self.correlator.add_ml(f, result):
                self._post_alert(self.alerts.emit_correlation(match))

        db.session.commit()
        self._flows_processed += len(flows)
        self._update_session_stats()

        return len(flows)

    def _update_session_stats(self) -> None:
        analysis = Analysis.query.get(self.session_id)
        if analysis:
            analysis.total_flows = self._flows_processed
            analysis.total_findings = self._alerts_count
            analysis.progress_pct = min(99, analysis.progress_pct + 1)
            db.session.commit()

    def run_loop(self, stop_event: threading.Event, poll_interval: float = 2.0):
        logger.info("Live monitor started for session %s", self.session_id)
        while not stop_event.is_set():
            try:
                self.process_batch()
            except Exception as exc:
                logger.exception("Live monitor batch error: %s", exc)
            stop_event.wait(poll_interval)

        analysis = Analysis.query.get(self.session_id)
        if analysis:
            analysis.status = "complete"
            analysis.completed_at = datetime.now(timezone.utc)
            analysis.progress_pct = 100
            db.session.commit()
        logger.info("Live monitor stopped for session %s", self.session_id)


def start_monitor(app, session_id: str) -> bool:
    if session_id in _active_monitors and _active_monitors[session_id].is_alive():
        return False

    stop_event = threading.Event()
    _stop_flags[session_id] = stop_event

    def _target():
        with app.app_context():
            monitor = LiveMonitor(dict(app.config), session_id)
            monitor.run_loop(stop_event)

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


def monitor_status(session_id: str) -> dict:
    thread = _active_monitors.get(session_id)
    running = thread is not None and thread.is_alive()
    analysis = Analysis.query.get(session_id)
    return {
        "session_id": session_id,
        "running": running,
        "status": analysis.status if analysis else "unknown",
        "total_flows": analysis.total_flows if analysis else 0,
        "total_findings": analysis.total_findings if analysis else 0,
        "progress_pct": analysis.progress_pct if analysis else 0,
    }
