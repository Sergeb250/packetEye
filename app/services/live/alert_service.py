"""Real-time alert emission for live NIDS."""

import logging
import time
import uuid
from collections import deque

from app.extensions import cache, db
from app.models.analysis import Finding
from app.services.detection.scoring import severity_to_score
from app.services.net_utils import is_external_ip, ml_alert_suppressed

logger = logging.getLogger(__name__)


class AlertService:
    def __init__(
        self,
        session_id: str,
        rate_limit_per_minute: int = 60,
        threshold: float = 5.0,
        webhook=None,
        whitelist=None,
    ):
        self.session_id = session_id
        self.rate_limit = rate_limit_per_minute
        self.threshold = threshold
        self.webhook = webhook
        self.whitelist = whitelist
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
        # Tiers ride on the configured threshold so retuning it keeps the
        # critical/high bands meaningful instead of anchored to old constants.
        if score >= min(self.threshold + 2.0, 9.5):
            return "critical"
        if score >= self.threshold + 1.0:
            return "high"
        return "medium"

    def emit(self, flow_dict: dict, ml_result: dict) -> dict | None:
        if not ml_result.get("flagged"):
            return None
        suppressed, reason = ml_alert_suppressed(flow_dict, self.whitelist)
        if suppressed:
            logger.debug("ML alert suppressed for %s → %s: %s", flow_dict.get("src_ip"), flow_dict.get("dst_ip"), reason)
            return None
        if not self._allowed():
            logger.debug("Alert rate limit reached for session %s", self.session_id)
            return None

        score = ml_result.get("anomaly_score", 0)
        severity = self._severity_for_score(score)
        external = is_external_ip(flow_dict.get("dst_ip") or "")

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
        }

        finding = Finding(
            analysis_id=self.session_id,
            flow_id=flow_dict.get("id"),
            rule_id="ML-ANOMALY-001",
            source="ml",
            title=(
                "Live ML Anomaly — outlier flow to external host"
                if external
                else "Live ML Anomaly — unusual traffic pattern"
            ),
            description=ml_result.get("explanation", ""),
            severity=severity,
            severity_score=score,
            evidence={
                "anomaly_score": score,
                "explanation": ml_result.get("explanation"),
                "live": True,
                **{k: flow_dict.get(k) for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")},
            },
            mitre_tactic="TA0011 - Command and Control" if external else None,
            mitre_technique="T1071 - Application Layer Protocol" if external else None,
            recommendation=(
                "Investigate source host and block external destination if confirmed malicious."
                if external
                else "Review local traffic pattern; unlikely to be Internet C2."
            ),
        )
        db.session.add(finding)
        db.session.commit()

        alert["finding_id"] = finding.id
        self._push_to_feed(alert)
        if self.webhook:
            self.webhook.notify(alert)
        self._maybe_enhance(alert, finding.id)
        return alert

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
        """Surface a Suricata signature hit as a live finding + feed alert."""
        flow_check = {
            "src_ip": alert_dict.get("src_ip"),
            "dst_ip": alert_dict.get("dst_ip"),
            "src_port": alert_dict.get("src_port"),
            "dst_port": alert_dict.get("dst_port"),
            "protocol": alert_dict.get("protocol"),
        }
        suppressed, reason = ml_alert_suppressed(flow_check, self.whitelist)
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

        finding = Finding(
            analysis_id=self.session_id,
            rule_id=f"SURICATA-{alert_dict.get('signature_id') or 'SIG'}",
            source="suricata",
            title=signature,
            description=description,
            severity=severity,
            severity_score=severity_to_score(severity),
            evidence={
                "signature_id": alert_dict.get("signature_id"),
                "category": category,
                "action": alert_dict.get("action"),
                "app_proto": alert_dict.get("app_proto"),
                "live": True,
                **{k: alert_dict.get(k) for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")},
            },
            recommendation="Review the matched signature and validate the traffic between these hosts.",
        )
        db.session.add(finding)
        db.session.commit()

        alert["finding_id"] = finding.id
        self._push_to_feed(alert)
        if self.webhook:
            self.webhook.notify(alert)
        self._maybe_enhance(alert, finding.id)
        return alert

    def emit_correlation(self, match: dict) -> dict | None:
        """Suricata signature + ML anomaly on the same host pair — critical."""
        if not self._allowed():
            return None

        title = f"Correlated: {match.get('signature') or 'signature'} + ML anomaly"
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
        }

        finding = Finding(
            analysis_id=self.session_id,
            flow_id=match.get("flow_id"),
            rule_id=f"CORR-{match.get('signature_id') or 'ML'}",
            source="suricata_ml_correlation",
            title=title,
            description=description,
            severity="critical",
            severity_score=9.5,
            evidence={
                "signature": match.get("signature"),
                "signature_id": match.get("signature_id"),
                "category": match.get("category"),
                "anomaly_score": match.get("anomaly_score"),
                "ml_explanation": match.get("ml_explanation"),
                "live": True,
                **{k: match.get(k) for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")},
            },
            recommendation=(
                "Signature and anomaly agreement is high-confidence. Isolate the source host, "
                "then investigate the destination with OSINT."
            ),
        )
        db.session.add(finding)
        db.session.commit()

        alert["finding_id"] = finding.id
        self._push_to_feed(alert)
        if self.webhook:
            self.webhook.notify(alert)
        return alert

    def _push_to_feed(self, alert: dict) -> None:
        cache_key = f"live:alerts:{self.session_id}"
        try:
            existing = cache.get(cache_key) or []
            if isinstance(existing, str):
                import json

                existing = json.loads(existing)
            existing.append(alert)
            existing = existing[-200:]
            cache.set(cache_key, existing, timeout=86400)
        except Exception as exc:
            logger.debug("Alert cache failed: %s", exc)

    @staticmethod
    def get_alerts(session_id: str, since_ts: float = 0) -> list:
        cache_key = f"live:alerts:{session_id}"
        try:
            alerts = cache.get(cache_key) or []
            if isinstance(alerts, str):
                import json

                alerts = json.loads(alerts)
            return [a for a in alerts if a.get("timestamp", 0) > since_ts]
        except Exception:
            return []
