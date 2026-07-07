"""Send escalation emails via SMTP (Google Gmail compatible)."""

from __future__ import annotations

import logging
import re
import smtplib
from email.message import EmailMessage

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_email(addr: str) -> bool:
    return bool(_EMAIL_RE.match((addr or "").strip()))


def send_escalation_email(
    config: dict,
    *,
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
) -> dict:
    if not config.get("SMTP_ENABLED", False):
        return {"ok": False, "error": "SMTP disabled (SMTP_ENABLED=false)"}

    to_addr = (to or "").strip()
    if not _valid_email(to_addr):
        return {"ok": False, "error": "Invalid recipient email address"}

    smtp_user = (config.get("SMTP_USER") or "").strip()
    smtp_pass = (config.get("SMTP_PASSWORD") or "").strip()
    if not smtp_user or not smtp_pass:
        return {"ok": False, "error": "SMTP_USER and SMTP_PASSWORD required in .env"}

    from_addr = (config.get("SMTP_FROM") or smtp_user).strip()
    host = config.get("SMTP_HOST", "smtp.gmail.com")
    port = int(config.get("SMTP_PORT", 587))

    msg = EmailMessage()
    msg["Subject"] = (subject or "packetEye alert escalation").strip()[:500]
    msg["From"] = from_addr
    msg["To"] = to_addr
    if cc and _valid_email(cc.strip()):
        msg["Cc"] = cc.strip()
    msg.set_content((body or "").strip())

    try:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        logger.info("Escalation email sent to %s", to_addr)
        return {"ok": True, "to": to_addr}
    except Exception as exc:
        logger.warning("Escalation email failed: %s", exc)
        return {"ok": False, "error": str(exc)[:300]}
