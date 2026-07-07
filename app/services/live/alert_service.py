"""Real-time alert emission for live NIDS."""

import logging
import time
import uuid
from collections import deque

from app.services.net_utils import is_external_ip, ml_alert_suppressed, suricata_alert_suppressed
from app.services.streams import get_alert_writer

logger = logging.getLogger(__name__)


class AlertService:
    def __init__(
        self,
        session_id: str,
        rate_limit_per_minute: int = 60,
        threshold: float = 5.0,
        webhook=None,
        whitelist=None,
        ml_strict_c2_filter: bool = True,
    ):
        self.session_id = session_id
        self.rate_limit = rate_limit_per_minute
        self.threshold = threshold
        self.webhook = webhook
        self.whitelist = whitelist
        self.ml_strict_c2_filter = ml_strict_c2_filter
        self._timestamps: deque = deque()

    def _allowed(self) -> bool:
        now = time.time()
        while self._timestamps and self._timestamps[0] < now - 60:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.rate_limit:
            return False
        self._timestamps.append(now)
        return True

    def _severity_for_score(self, score: float) -> str:
        if score >= min(self.threshold + 2.0, 9.5):
            return "critical"
        if score >= self.threshold + 1.0:
            return "high"
        return "medium"

    def _persist(self, alert: dict) -> None:
        writer = get_alert_writer()
        if writer:
            writer.write(alert)

    def _finalize(self, alert: dict, *, enhance: bool = True) -> dict:
        self._persist(alert)
        if self.webhook:
            self.webhook.notify(alert)
        if enhance:
            self._maybe_enhance(alert, alert.get("finding_id") or alert.get("id") or "")
        return alert

    def emit(self, flow_dict: dict, ml_result: dict) -> dict | None:
        if not ml_result.get("flagged"):
            return None
        suppressed, reason = ml_alert_suppressed(
            flow_dict, self.whitelist, strict_c2_filter=self.ml_strict_c2_filter
        )
        if suppressed:
            logger.debug("ML alert suppressed for %s → %s: %s", flow_dict.get("src_ip"), flow_dict.get("dst_ip"), reason)
            return None
        if not self._allowed():
            logger.debug("Alert rate limit reached for session %s", self.session_id)
            return None

        score = ml_result.get("anomaly_score", 0)
        severity = self._severity_for_score(score)

        alert = {
            "id": str(uuid.uuid4()),
            "session_id": self.session_id,
            "type": "ml",
            "timestamp": time.time(),
            "severity": severity,
            "anomaly_score": score,
            "explanation": ml_result.get("explanation", ""),
            "src_ip": flow_dict.get("src_ip"),
            "dst_ip": flow_dict.get("dst_ip"),
            "src_port": flow_dict.get("src_port"),
            "dst_port": flow_dict.get("dst_port"),
            "protocol": flow_dict.get("protocol"),
            "total_fwd_packets": flow_dict.get("total_fwd_packets"),
            "total_bwd_packets": flow_dict.get("total_bwd_packets"),
            "total_fwd_bytes": flow_dict.get("total_fwd_bytes"),
            "total_bwd_bytes": flow_dict.get("total_bwd_bytes"),
            "flow_duration": flow_dict.get("flow_duration"),
            "flow_id": flow_dict.get("id"),
        }
        alert["finding_id"] = alert["id"]
        return self._finalize(alert)

    def _maybe_enhance(self, alert: dict, finding_id: str) -> None:
        try:
            from flask import current_app
            cfg = dict(current_app.config)
            if cfg.get("ALERT_ENHANCED_ANALYSIS") or cfg.get("LLM_LIVE_ALERT_SYNTHESIS"):
                from app.services.live.alert_enricher import kickoff_enhanced_alert
                kickoff_enhanced_alert(current_app._get_current_object(), finding_id, alert)
        except Exception as exc:
            logger.debug("Enhanced alert skip: %s", exc)

    def emit_suricata(self, alert_dict: dict) -> dict | None:
        """Surface a Suricata signature hit as a live feed alert."""
        flow_check = {
            "src_ip": alert_dict.get("src_ip"),
            "dst_ip": alert_dict.get("dst_ip"),
            "src_port": alert_dict.get("src_port"),
            "dst_port": alert_dict.get("dst_port"),
            "protocol": alert_dict.get("protocol"),
        }
        suppressed, reason = suricata_alert_suppressed(flow_check, self.whitelist)
        if suppressed:
            logger.debug("Suricata alert suppressed: %s", reason)
            return None
        if not self._allowed():
            logger.debug("Alert rate limit reached for session %s", self.session_id)
            return None

        severity = alert_dict.get("severity", "medium")
        signature = alert_dict.get("signature", "Suricata signature")
        category = alert_dict.get("category") or ""
        description = f"Suricata signature hit: {signature}" + (f" ({category})" if category else "")

        alert = {
            "id": str(uuid.uuid4()),
            "session_id": self.session_id,
            "type": "suricata",
            "timestamp": time.time(),
            "severity": severity,
            "signature": signature,
            "signature_id": alert_dict.get("signature_id"),
            "category": category,
            "explanation": description,
            "src_ip": alert_dict.get("src_ip"),
            "dst_ip": alert_dict.get("dst_ip"),
            "src_port": alert_dict.get("src_port"),
            "dst_port": alert_dict.get("dst_port"),
            "protocol": alert_dict.get("protocol"),
        }
        alert["finding_id"] = alert["id"]
        return self._finalize(alert)

    def emit_correlation(self, match: dict) -> dict | None:
        """Suricata signature + ML anomaly on the same host pair — critical."""
        if not self._allowed():
            return None

        description = (
            f"Suricata matched '{match.get('signature')}' and the ML baseline flagged the same "
            f"host pair (score {match.get('anomaly_score')}) within the correlation window."
        )

        alert = {
            "id": str(uuid.uuid4()),
            "session_id": self.session_id,
            "type": "correlation",
            "timestamp": time.time(),
            "severity": "critical",
            "anomaly_score": match.get("anomaly_score"),
            "signature": match.get("signature"),
            "explanation": description,
            "src_ip": match.get("src_ip"),
            "dst_ip": match.get("dst_ip"),
            "src_port": match.get("src_port"),
            "dst_port": match.get("dst_port"),
            "protocol": match.get("protocol"),
            "flow_id": match.get("flow_id"),
        }
        alert["finding_id"] = alert["id"]
        return self._finalize(alert, enhance=False)

    @staticmethod
    def get_alerts(session_id: str, since_ts: float = 0) -> list:
        from app.services.streams.alert_writer import AlertStreamWriter

        return AlertStreamWriter.get_alerts(session_id, since_ts)

    def emit_prepared(self, alert: dict) -> dict:
        """Persist a fully-built alert dict (e.g. LLM packet triage)."""
        alert = dict(alert)
        alert.setdefault("id", str(uuid.uuid4()))
        alert.setdefault("session_id", self.session_id)
        alert.setdefault("timestamp", time.time())
        alert["finding_id"] = alert.get("finding_id") or alert["id"]
        return self._finalize(alert, enhance=False)
