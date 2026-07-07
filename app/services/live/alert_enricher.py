"""Async enhanced alert synthesis: OSINT + LLM for live alerts."""

from __future__ import annotations

import json
import logging
import threading

from app.models.analysis import Observable
from app.services.enrichment.orchestrator import EnrichmentOrchestrator
from app.services.llm.ensemble import get_llm_ensemble
from app.services.llm.prompts import LIVE_ALERT_SYNTH_PROMPT, SYSTEM_ANALYST
from app.services.llm.tokens import with_tier
from app.services.streams import get_alert_writer

logger = logging.getLogger(__name__)

CIC_LABELS = (
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
    "DoS slowloris", "FTP-Patator", "PortScan", "SSH-Patator",
    "Web Attack – Brute Force", "Infiltration",
)


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

    evidence = {
        k: alert.get(k)
        for k in (
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "anomaly_score", "signature", "signature_id", "category", "flow_id",
        )
        if alert.get(k) is not None
    }
    dst = alert.get("dst_ip") or evidence.get("dst_ip") or ""
    osint = {}
    if dst:
        osint = _load_osint_sync(config, dst, str(alert.get("session_id") or "live"))

    enhanced = {"osint": osint}
    if config.get("LLM_LIVE_ALERT_SYNTHESIS") and config.get("LLM_ENABLED"):
        try:
            brief_cfg = with_tier(dict(config), "brief")
            ensemble = get_llm_ensemble(brief_cfg)
            user = LIVE_ALERT_SYNTH_PROMPT.format(
                cic_labels=", ".join(CIC_LABELS),
                alert=json.dumps(alert, default=str)[:4000],
                evidence=json.dumps(evidence, default=str)[:4000],
                osint=json.dumps(osint, default=str)[:4000],
            )
            parsed = ensemble.complete_json(SYSTEM_ANALYST, user, 0.2, cache_prefix="live_alert")
            if parsed:
                enhanced.update(parsed)
        except Exception as exc:
            logger.warning("LLM live synthesis failed: %s", exc)
            enhanced["llm_error"] = str(exc)

    patch: dict = {"enhanced": enhanced}
    if enhanced.get("summary"):
        patch["explanation"] = enhanced["summary"]
    if enhanced.get("severity") in ("info", "medium", "high", "critical"):
        patch["severity"] = enhanced["severity"]

    session_id = str(alert.get("session_id") or "")
    writer = get_alert_writer()
    if writer and session_id:
        writer.update(session_id, finding_id, patch)

    alert["enhanced"] = enhanced
    return enhanced


def kickoff_enhanced_alert(app, finding_id: str, alert: dict) -> None:
    config = dict(app.config)

    def _run():
        with app.app_context():
            try:
                synthesize_live_alert(config, finding_id, dict(alert))
            except Exception as exc:
                logger.warning("Enhanced alert thread failed: %s", exc)

    threading.Thread(target=_run, daemon=True, name=f"enhance-{finding_id[:8]}").start()
