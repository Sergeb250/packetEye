"""Push live alerts to a Discord-compatible webhook."""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_COLORS = {"low": 0x6C757D, "medium": 0x0DCAF0, "high": 0xFFC107, "critical": 0xDC3545}


class WebhookNotifier:
    """Posts alert embeds to ALERT_WEBHOOK_URL, respecting severity + rate caps."""

    def __init__(self, config: dict):
        self.url = str(config.get("ALERT_WEBHOOK_URL") or "").strip()
        self.min_severity = str(config.get("ALERT_WEBHOOK_MIN_SEVERITY") or "high").lower()
        self.rate_limit = max(1, int(config.get("ALERT_WEBHOOK_RATE_LIMIT", 10)))
        self._timestamps: deque = deque()

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def _allowed(self) -> bool:
        now = time.time()
        while self._timestamps and self._timestamps[0] < now - 60:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.rate_limit:
            return False
        self._timestamps.append(now)
        return True

    def _passes_severity(self, severity: str) -> bool:
        return SEVERITY_ORDER.get(str(severity).lower(), 1) >= SEVERITY_ORDER.get(self.min_severity, 2)

    def _build_payload(self, alert: dict) -> dict:
        severity = str(alert.get("severity") or "medium").lower()
        is_suricata = alert.get("type") == "suricata"
        title = (
            f"Suricata: {alert.get('signature', 'signature hit')}"
            if is_suricata
            else f"ML Anomaly (score {alert.get('anomaly_score', '?')})"
        )
        fields = [
            {
                "name": "Connection",
                "value": (
                    f"`{alert.get('src_ip', '?')}:{alert.get('src_port', '*')} → "
                    f"{alert.get('dst_ip', '?')}:{alert.get('dst_port', '*')}` ({alert.get('protocol', '?')})"
                ),
                "inline": False,
            },
            {"name": "Severity", "value": severity.upper(), "inline": True},
        ]
        if is_suricata and alert.get("category"):
            fields.append({"name": "Category", "value": str(alert["category"])[:256], "inline": True})

        return {
            "username": "packetEye NIDS",
            "content": f"🚨 **{severity.upper()}** — {title}",
            "embeds": [
                {
                    "title": title[:256],
                    "description": str(alert.get("explanation") or "")[:1000],
                    "color": SEVERITY_COLORS.get(severity, 0x0DCAF0),
                    "fields": fields,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "footer": {"text": f"session {str(alert.get('session_id', ''))[:8]}"},
                }
            ],
        }

    def notify(self, alert: dict) -> bool:
        if not self.enabled:
            return False
        if not self._passes_severity(alert.get("severity", "medium")):
            return False
        if not self._allowed():
            logger.debug("Webhook rate limit reached; dropping alert")
            return False

        try:
            import requests

            resp = requests.post(self.url, json=self._build_payload(alert), timeout=5)
            if resp.status_code >= 400:
                logger.warning("Alert webhook returned %s: %s", resp.status_code, resp.text[:200])
                return False
            return True
        except Exception as exc:
            logger.warning("Alert webhook failed: %s", exc)
            return False

    def send_test(self) -> dict:
        if not self.enabled:
            return {"ok": False, "error": "ALERT_WEBHOOK_URL is not configured in .env."}
        ok = self.notify(
            {
                "type": "ml",
                "severity": "critical",
                "anomaly_score": 9.9,
                "explanation": "Test alert from packetEye — webhook connectivity check.",
                "src_ip": "203.0.113.10",
                "src_port": 44444,
                "dst_ip": "192.0.2.20",
                "dst_port": 22,
                "protocol": "TCP",
                "session_id": "webhook-test",
            }
        )
        return {"ok": ok} if ok else {"ok": False, "error": "Webhook POST failed — check the URL and logs."}
