"""Push live alerts to a Discord-compatible webhook."""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timezone

from app.services.integrations.store import get_discord_config

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "info": 0x6C757D,
    "low": 0x6C757D,
    "medium": 0x0DCAF0,
    "high": 0xFFC107,
    "critical": 0xDC3545,
}


class WebhookNotifier:
    """Posts alert embeds to Discord, respecting multi-select filters + rate caps."""

    def __init__(self, config: dict | None = None):
        self._app_config = dict(config or {})
        self._timestamps: deque = deque()

    def _reload(self) -> dict:
        return get_discord_config(self._app_config)

    @property
    def enabled(self) -> bool:
        dc = self._reload()
        return bool(dc.get("enabled") and dc.get("url"))

    @property
    def url(self) -> str:
        return str(self._reload().get("url") or "").strip()

    @property
    def rate_limit(self) -> int:
        return max(1, int(self._reload().get("rate_limit_per_minute") or 10))

    def _allowed(self) -> bool:
        now = time.time()
        limit = self.rate_limit
        while self._timestamps and self._timestamps[0] < now - 60:
            self._timestamps.popleft()
        if len(self._timestamps) >= limit:
            return False
        self._timestamps.append(now)
        return True

    def _passes_filters(self, alert: dict, dc: dict) -> bool:
        severity = str(alert.get("severity") or "medium").lower()
        severities = [str(s).lower() for s in (dc.get("severities") or ["all"])]
        if "all" not in severities and severity not in severities:
            return False

        alert_type = str(alert.get("type") or "ml").lower()
        sources = [str(s).lower() for s in (dc.get("sources") or ["all"])]
        if "all" not in sources and alert_type not in sources:
            return False

        if alert_type == "llm":
            ai_status = str(alert.get("ai_status") or "open").lower()
            statuses = [str(s).lower() for s in (dc.get("ai_statuses") or ["all"])]
            if "all" not in statuses and ai_status not in statuses:
                return False

        return True

    def _alert_title(self, alert: dict) -> str:
        alert_type = str(alert.get("type") or "ml").lower()
        if alert_type == "suricata":
            return f"Suricata: {alert.get('signature', 'signature hit')}"
        if alert_type == "correlation":
            sig = alert.get("signature") or "signature"
            score = alert.get("anomaly_score", "?")
            return f"Correlation: {sig} + ML score {score}"
        if alert_type == "llm":
            attack = alert.get("attack_type") or "AI triage hit"
            status = alert.get("ai_status") or "open"
            return f"AI Triage ({status.replace('_', ' ')}): {attack}"
        return f"ML Anomaly (score {alert.get('anomaly_score', '?')})"

    def _build_payload(self, alert: dict) -> dict:
        severity = str(alert.get("severity") or "medium").lower()
        alert_type = str(alert.get("type") or "ml").lower()
        title = self._alert_title(alert)
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
            {"name": "Source", "value": alert_type.upper(), "inline": True},
        ]
        if alert_type == "suricata" and alert.get("category"):
            fields.append({"name": "Category", "value": str(alert["category"])[:256], "inline": True})
        if alert_type == "llm" and alert.get("ai_status"):
            fields.append({
                "name": "AI status",
                "value": str(alert["ai_status"]).replace("_", " ").title(),
                "inline": True,
            })

        return {
            "username": "packetEye NIDS",
            "content": f"**{severity.upper()}** — {title}",
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
        dc = self._reload()
        if not dc.get("enabled") or not dc.get("url"):
            return False
        if not self._passes_filters(alert, dc):
            return False
        if not self._allowed():
            logger.debug("Webhook rate limit reached; dropping alert")
            return False

        try:
            import requests

            resp = requests.post(dc["url"], json=self._build_payload(alert), timeout=5)
            if resp.status_code >= 400:
                logger.warning("Alert webhook returned %s: %s", resp.status_code, resp.text[:200])
                return False
            return True
        except Exception as exc:
            logger.warning("Alert webhook failed: %s", exc)
            return False

    def send_test(self) -> dict:
        if not self.enabled:
            return {"ok": False, "error": "Discord webhook is not enabled or URL is missing. Configure it in Integrations."}
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


def get_webhook_notifier(config: dict | None = None) -> WebhookNotifier | None:
    """Return a notifier when Discord integration is enabled with a URL."""
    notifier = WebhookNotifier(config)
    return notifier if notifier.enabled else None
