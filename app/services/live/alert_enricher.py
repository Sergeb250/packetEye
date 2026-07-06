"""Async enhanced alert synthesis: OSINT + LLM for live findings."""

from __future__ import annotations

import json
import logging
import threading

from app.extensions import db
from app.models.analysis import Finding, Observable
from app.services.enrichment.orchestrator import EnrichmentOrchestrator
from app.services.llm.analyst import LLMAnalyst
from app.services.llm.prompts import SYSTEM_ANALYST

logger = logging.getLogger(__name__)

CIC_LABELS = (
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
    "DoS slowloris", "FTP-Patator", "PortScan", "SSH-Patator",
    "Web Attack – Brute Force", "Infiltration",
)

LIVE_ALERT_SYNTH_PROMPT = """You are a SOC analyst synthesizing a live NIDS alert.

CIC-IDS2017 attack labels (pick the most probable): {cic_labels}

Alert JSON: {alert}
Flow/evidence JSON: {evidence}
OSINT JSON: {osint}

Rules:
- Downgrade false positives for known CDN/cloud (Google 142.251.x, 172.217.x on 443/TLS, Cloudflare, Microsoft).
- If OSINT is clean and only ML anomaly with no Suricata rule, prefer BENIGN or low severity.
- Map traffic patterns to CIC labels (port sweep → PortScan, beacon → Bot, flood → DDoS).

Respond ONLY with JSON:
{{"probable_attack_type": "...", "severity": "info|medium|high|critical", "confidence": 0.0-1.0,
"summary": "2-3 sentences for analyst", "recommended_action": "...",
"false_positive_risk": "low|medium|high", "network_summary": "...", "iocs": []}}"""


def _load_osint_sync(config: dict, ip: str, session_id: str = "live") -> dict:
    if not ip:
        return {}
    orch = EnrichmentOrchestrator(config)
    obs = Observable(analysis_id=str(session_id), type="ip", value=ip)
    try:
        from app.services.enrichment.async_runner import run_async

        return run_async(orch.enrich_observable(obs))
    except Exception as exc:
        logger.warning("OSINT for live alert failed: %s", exc)
        return {"error": str(exc)}


def synthesize_live_alert(config: dict, finding_id: str, alert: dict) -> dict | None:
    if not config.get("ALERT_ENHANCED_ANALYSIS") and not config.get("LLM_LIVE_ALERT_SYNTHESIS"):
        return None
    finding = Finding.query.get(finding_id)
    if not finding:
        return None

    evidence = dict(finding.evidence or {})
    dst = alert.get("dst_ip") or evidence.get("dst_ip") or ""
    osint = {}
    if dst:
        osint = _load_osint_sync(config, dst, str(alert.get("session_id") or "live"))

    enhanced = {"osint": osint}
    if config.get("LLM_LIVE_ALERT_SYNTHESIS") and config.get("LLM_ENABLED"):
        try:
            analyst = LLMAnalyst(config)
            user = LIVE_ALERT_SYNTH_PROMPT.format(
                cic_labels=", ".join(CIC_LABELS),
                alert=json.dumps(alert, default=str)[:8000],
                evidence=json.dumps(evidence, default=str)[:8000],
                osint=json.dumps(osint, default=str)[:8000],
            )
            parsed = analyst._cached_or_call("live_alert", user, SYSTEM_ANALYST, user)
            if parsed:
                enhanced.update(parsed)
        except Exception as exc:
            logger.warning("LLM live synthesis failed: %s", exc)
            enhanced["llm_error"] = str(exc)

    evidence["enhanced"] = enhanced
    finding.evidence = evidence
    if enhanced.get("summary"):
        finding.description = enhanced["summary"]
    if enhanced.get("severity") in ("info", "medium", "high", "critical"):
        finding.severity = enhanced["severity"]
    if enhanced.get("recommended_action"):
        finding.recommendation = enhanced["recommended_action"]
    db.session.commit()
    alert["enhanced"] = enhanced
    return enhanced


def kickoff_enhanced_alert(app, finding_id: str, alert: dict) -> None:
    config = dict(app.config)

    def _run():
        try:
            with app.app_context():
                synthesize_live_alert(config, finding_id, dict(alert))
        except Exception as exc:
            logger.warning("Enhanced alert thread failed: %s", exc)

    threading.Thread(target=_run, daemon=True, name=f"enhance-{finding_id[:8]}").start()
