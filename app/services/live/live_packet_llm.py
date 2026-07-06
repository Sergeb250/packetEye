"""Live LLM packet triage — sample packet feed, dual-model analysis, triage registry."""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import deque

from flask import Flask

from app.extensions import cache, db
from app.models.analysis import Finding
from app.services.capture import orchestrator as capture_orchestrator
from app.services.detection.scoring import severity_to_score
from app.services.live import packet_feed
from app.services.live.alert_service import AlertService
from app.services.live.session_utils import resolve_live_session_id
from app.services.live.triage_heuristics import TriageHeuristics
from app.services.live.triage_registry import build_incident_row, update_incident, upsert_incident
from app.services.llm.router import get_model_router
from app.services.llm.stack import stack_model_names
from app.services.llm.provider import parse_json_response

logger = logging.getLogger(__name__)

CACHE_KEY = "live:llm_packet_analysis"
CIC_LABELS = (
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
    "DoS slowloris", "FTP-Patator", "PortScan", "SSH-Patator", "Web Attack Brute Force",
    "Web Attack XSS", "Infiltration", "Heartbleed",
)
PACKET_SYSTEM = (
    "You are a SOC packet triage engine. Classify one network event quickly. "
    "Respond ONLY with valid JSON, no markdown."
)
PACKET_USER = """Network event JSON:
{packet}

CIC-IDS2017 labels (pick best match): {cic_labels}

Is this suspicious (scan, SSH brute force, C2, exfil, malware, DoS)?
JSON schema:
{{"suspicious": true|false, "severity": "info|medium|high|critical", "confidence": 0.0-1.0,
 "attack_type": "CIC label e.g. SSH-Patator or BENIGN", "disposition_suggested": "true_positive|true_negative|benign",
 "summary": "one sentence for analyst", "indicators": ["ssh_syn_flood", "..."]}}"""

_state: dict = {
    "running": False,
    "stop_event": None,
    "thread": None,
    "app": None,
    "session_id": None,
    "stats": {},
    "heuristics": None,
    "context_log": deque(maxlen=40),
}


def _fast_providers(config: dict) -> list[tuple[str, object]]:
    """Legacy helper — prefer get_model_router(config)."""
    from app.services.llm.stack import build_live_stack

    timeout = float(config.get("LLM_LIVE_TIMEOUT_SECONDS", 18))
    stack = build_live_stack(config, max_models=3)
    n = len(stack) or 1
    per_model = max(64, int(config.get("LLM_LIVE_PACKET_MAX_TOKENS", 256)) // n)
    for _, prov in stack:
        if hasattr(prov, "max_tokens"):
            prov.max_tokens = per_model
        if hasattr(prov, "timeout"):
            prov.timeout = timeout
    return stack


def _compact_packet(pkt: dict) -> str:
    slim = {
        k: pkt.get(k)
        for k in (
            "timestamp", "event_type", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "length", "info", "severity", "source",
        )
        if pkt.get(k) is not None
    }
    extra = pkt.get("extra") or {}
    for key in ("signature_id", "category", "app_proto"):
        if extra.get(key):
            slim[key] = extra[key]
    return json.dumps(slim, default=str)[:1800]


def _call_model(name: str, provider, packet_json: str) -> tuple[str, dict, str | None]:
    user = PACKET_USER.format(packet=packet_json, cic_labels=", ".join(CIC_LABELS))
    try:
        raw = provider.complete(PACKET_SYSTEM, user, temperature=0.1)
        parsed = parse_json_response(raw or "")
        if parsed:
            parsed["_model"] = name
            return name, parsed, None
        return name, {}, "empty or unparseable response"
    except Exception as exc:
        logger.debug("Live packet LLM %s failed: %s", name, exc)
        return name, {}, str(exc)


def _merge_verdicts(results: list[dict], min_confidence: float) -> dict | None:
    suspicious = [r for r in results if r.get("suspicious")]
    if not suspicious:
        return None
    best = max(suspicious, key=lambda r: float(r.get("confidence") or 0))
    if float(best.get("confidence") or 0) < min_confidence:
        if len(suspicious) < 2:
            return None
    sev_rank = {"info": 0, "medium": 1, "high": 2, "critical": 3}
    severity = max(
        (str(r.get("severity") or "medium").lower() for r in suspicious),
        key=lambda s: sev_rank.get(s, 1),
    )
    models = ", ".join(sorted({str(r.get("_model") or "?") for r in suspicious}))
    return {
        "suspicious": True,
        "severity": severity,
        "confidence": max(float(r.get("confidence") or 0) for r in suspicious),
        "attack_type": best.get("attack_type") or "Suspicious traffic",
        "summary": best.get("summary") or "LLM flagged suspicious packet activity.",
        "models": models,
        "indicators": best.get("indicators") or [],
        "disposition_suggested": best.get("disposition_suggested") or "true_positive",
    }


def _disposition_from_results(results: list[dict], merged: dict | None, errors: list[str]) -> str:
    if errors and not results:
        return "error"
    if merged and merged.get("suspicious"):
        disp = str(merged.get("disposition_suggested") or "true_positive").lower()
        if disp in ("true_positive", "open"):
            return "true_positive"
        return disp if disp in ("true_positive", "false_positive", "true_negative", "benign") else "open"
    if results and all(not r.get("suspicious") for r in results):
        disp = str(results[0].get("disposition_suggested") or "true_negative").lower()
        return disp if disp in ("true_negative", "benign") else "true_negative"
    return "open"


def _map_model_outputs(model_outputs: dict[str, dict]) -> tuple[dict, dict, dict]:
    primary = model_outputs.get("zai") or model_outputs.get("primary") or {}
    secondary = model_outputs.get("nvidia") or model_outputs.get("secondary") or {}
    tertiary = model_outputs.get("nvidia_secondary") or model_outputs.get("openrouter") or model_outputs.get("tertiary") or {}
    if not primary and model_outputs:
        keys = list(model_outputs.keys())
        primary = model_outputs.get(keys[0], {})
        if len(keys) > 1:
            secondary = model_outputs.get(keys[1], {})
        if len(keys) > 2:
            tertiary = model_outputs.get(keys[2], {})
    return primary, secondary, tertiary


def _push_context_entry(packet: dict, model_outputs: dict, merged: dict | None, errors: list[str]) -> None:
    primary, secondary, tertiary = _map_model_outputs(model_outputs)
    entry = {
        "timestamp": time.time(),
        "connection": f"{packet.get('src_ip')}:{packet.get('src_port', '')} → {packet.get('dst_ip')}:{packet.get('dst_port', '')}",
        "info": packet.get("info") or "",
        "zai": primary.get("summary") or primary.get("attack_type") or "—",
        "nvidia": secondary.get("summary") or secondary.get("attack_type") or "—",
        "tertiary": tertiary.get("summary") or tertiary.get("attack_type") or "—",
        "merged": (merged or {}).get("summary") or "cleared",
        "disposition": (merged or {}).get("disposition_suggested") or "benign",
        "errors": errors[:3],
        "models": list(model_outputs.keys()),
    }
    log = _state.get("context_log")
    if log is not None:
        log.appendleft(entry)


def _register_triage_row(
    session_id: str,
    packet: dict,
    *,
    primary: dict,
    secondary: dict,
    tertiary: dict | None = None,
    merged: dict | None,
    errors: list[str],
    sources: list[str],
    heuristic: dict | None = None,
) -> dict:
    tertiary = tertiary or {}
    disposition = _disposition_from_results(
        [r for r in (primary, secondary, tertiary) if r],
        merged,
        errors,
    )
    if heuristic and disposition in ("true_negative", "benign", "open"):
        disposition = "open"
    attack = (merged or heuristic or {}).get("attack_type") or "Unknown"
    if primary.get("attack_type") and attack == "Unknown":
        attack = primary["attack_type"]
    severity = (merged or heuristic or primary or {}).get("severity") or "info"
    confidence = float((merged or heuristic or primary or {}).get("confidence") or 0)
    summary = (merged or {}).get("summary") or primary.get("summary") or secondary.get("summary") or ""
    if heuristic and not summary:
        summary = heuristic.get("summary", "")
    indicators = list((merged or {}).get("indicators") or [])
    if heuristic:
        indicators.extend(heuristic.get("indicators") or [])

    row = build_incident_row(
        session_id=session_id,
        src_ip=packet.get("src_ip") or "",
        dst_ip=packet.get("dst_ip") or "",
        src_port=packet.get("src_port") or 0,
        dst_port=packet.get("dst_port") or 0,
        protocol=packet.get("protocol") or "TCP",
        sources=sources,
        attack_type=str(attack)[:120],
        severity=str(severity).lower(),
        confidence=confidence,
        disposition=disposition,
        llm_primary=primary,
        llm_secondary=secondary,
        llm_tertiary=tertiary,
        llm_merged_summary=summary,
        errors=errors,
        packet=packet,
        indicators=indicators,
        timestamp=packet.get("timestamp") or time.time(),
    )
    return upsert_incident(session_id, row)


def _emit_llm_packet_alert(
    app: Flask,
    session_id: str,
    packet: dict,
    verdict: dict,
    *,
    primary: dict | None = None,
    secondary: dict | None = None,
    tertiary: dict | None = None,
) -> dict | None:
    with app.app_context():
        config = dict(app.config)
        lab = bool(config.get("CAPTURE_LAB_ENABLED"))
        alerts = AlertService(session_id, ml_strict_c2_filter=not lab)
        severity = str(verdict.get("severity") or "medium").lower()
        if severity not in ("info", "medium", "high", "critical"):
            severity = "medium"

        summary = verdict.get("summary") or "LLM suspicious packet"
        attack = verdict.get("attack_type") or "Suspicious traffic"
        conf = float(verdict.get("confidence") or 0)

        alert = {
            "id": str(uuid.uuid4()),
            "session_id": session_id,
            "type": "llm",
            "from_ai": True,
            "timestamp": time.time(),
            "severity": severity,
            "explanation": summary,
            "attack_type": attack,
            "confidence": conf,
            "models": verdict.get("models"),
            "llm_primary": primary or {},
            "llm_secondary": secondary or {},
            "llm_tertiary": tertiary or {},
            "src_ip": packet.get("src_ip"),
            "dst_ip": packet.get("dst_ip"),
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "protocol": packet.get("protocol"),
        }

        finding = Finding(
            analysis_id=session_id,
            rule_id="LLM-PACKET-001",
            source="llm",
            title=f"AI triage — {attack}",
            description=summary,
            severity=severity,
            severity_score=severity_to_score(severity),
            evidence={
                "live": True,
                "llm_packet": True,
                "from_ai": True,
                "confidence": conf,
                "models": verdict.get("models"),
                "packet_info": packet.get("info"),
                **{k: packet.get(k) for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")},
            },
            recommendation="Validate with Suricata/ML alerts and OSINT on the destination.",
        )
        db.session.add(finding)
        db.session.commit()
        alert["finding_id"] = finding.id
        alerts._push_to_feed(alert)
        from app.services.live.triage_registry import register_from_alert

        register_from_alert(session_id, alert)
        return alert


def _emit_heuristic_alert(app: Flask, session_id: str, packet: dict, hit: dict) -> None:
    verdict = {
        "severity": hit.get("severity", "high"),
        "summary": hit.get("summary"),
        "attack_type": hit.get("attack_type"),
        "confidence": hit.get("confidence", 0.7),
        "models": "heuristic",
    }
    _emit_llm_packet_alert(app, session_id, packet, verdict)


def _resolve_session_id(config: dict, session_id: str | None) -> str | None:
    return resolve_live_session_id(config, session_id)


def _analysis_loop(app: Flask, poll_sec: float) -> None:
    stop_event: threading.Event = _state["stop_event"]
    session_id = _state["session_id"]
    last_packet_id = 0
    min_conf = float(app.config.get("LLM_LIVE_PACKET_MIN_CONFIDENCE", 0.55))
    heuristics: TriageHeuristics = _state.get("heuristics") or TriageHeuristics()

    with app.app_context():
        config = dict(app.config)
        interval = max(2.0, 60.0 / max(1, int(config.get("LLM_LIVE_PACKETS_PER_MIN", 30))))
        router = get_model_router(config)

        while not stop_event.is_set():
            try:
                packets = packet_feed.poll_packets(last_packet_id)
                if not packets:
                    stop_event.wait(poll_sec)
                    continue

                pkt = packets[-1]
                last_packet_id = max(last_packet_id, int(pkt.get("id") or 0))
                packet_json = _compact_packet(pkt)

                heuristic_hit = heuristics.analyze(pkt)
                sources = ["llm"]
                if heuristic_hit:
                    sources.append("heuristic")

                user = PACKET_USER.format(packet=packet_json, cic_labels=", ".join(CIC_LABELS))
                model_outputs, errors = router.parallel_triage(PACKET_SYSTEM, user, temperature=0.1)
                results = list(model_outputs.values())

                primary, secondary, tertiary = _map_model_outputs(model_outputs)

                _state["stats"]["packets_analyzed"] = _state["stats"].get("packets_analyzed", 0) + 1
                _state["stats"]["llm_calls"] = _state["stats"].get("llm_calls", 0) + len(model_outputs)
                _state["stats"]["last_packet_at"] = time.time()

                verdict = _merge_verdicts(results, min_conf)
                if heuristic_hit and (not verdict or float(heuristic_hit.get("confidence") or 0) > float((verdict or {}).get("confidence") or 0)):
                    verdict = {
                        "suspicious": True,
                        **heuristic_hit,
                        "models": "heuristic+llm" if results else "heuristic",
                    }

                _push_context_entry(pkt, model_outputs, verdict, errors)

                row = _register_triage_row(
                    session_id,
                    pkt,
                    primary=primary,
                    secondary=secondary,
                    tertiary=tertiary,
                    merged=verdict,
                    errors=errors,
                    sources=sources,
                    heuristic=heuristic_hit,
                )
                _state["stats"]["rows_logged"] = _state["stats"].get("rows_logged", 0) + 1

                if verdict and verdict.get("suspicious"):
                    _emit_llm_packet_alert(
                        app, session_id, pkt, verdict,
                        primary=primary, secondary=secondary, tertiary=tertiary,
                    )
                    _state["stats"]["alerts_emitted"] = _state["stats"].get("alerts_emitted", 0) + 1
                elif heuristic_hit and float(heuristic_hit.get("confidence") or 0) >= 0.75:
                    _emit_heuristic_alert(app, session_id, pkt, heuristic_hit)
                    _state["stats"]["alerts_emitted"] = _state["stats"].get("alerts_emitted", 0) + 1

            except Exception as exc:
                _state["stats"]["last_error"] = str(exc)
                logger.warning("Live packet LLM loop error: %s", exc)

            stop_event.wait(interval)

    _state["running"] = False


def _cache_status(extra: dict | None = None) -> dict:
    try:
        cached = cache.get(CACHE_KEY) or {}
        if isinstance(cached, str):
            cached = json.loads(cached)
    except Exception:
        cached = {}
    if extra:
        cached.update(extra)
    try:
        cache.set(CACHE_KEY, cached, timeout=86400)
    except Exception:
        pass
    return cached


def set_llm_packet_analysis(app: Flask, *, enabled: bool, session_id: str | None = None) -> dict:
    config = dict(app.config)
    if enabled and not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM disabled. Set LLM_ENABLED=true in .env"}
    if enabled and not (config.get("ZAI_API_KEY") or config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")):
        return {"ok": False, "error": "No LLM API key configured (set ZAI_API_KEY and/or NVIDIA_API_KEY)"}

    if enabled:
        sid = _resolve_session_id(config, session_id)
        if not sid:
            return {"ok": False, "error": "No active live ML session. Start capture + ML first."}

        cap = capture_orchestrator.capture_status(config)
        feed = packet_feed.feed_status()
        if not feed.get("running") and cap.get("running"):
            packet_feed.start_feed(
                config,
                mode=cap.get("mode") or "suricata",
                interface=cap.get("interface") or "",
                eve_path=(cap.get("suricata") or {}).get("eve", {}).get("path"),
            )

        if _state.get("running"):
            stop_llm_packet_analysis()

        stop_event = threading.Event()
        _state.update({
            "running": True,
            "stop_event": stop_event,
            "app": app,
            "session_id": sid,
            "heuristics": TriageHeuristics(),
            "stats": {"packets_analyzed": 0, "llm_calls": 0, "alerts_emitted": 0, "rows_logged": 0, "started_at": time.time()},
        })
        thread = threading.Thread(
            target=_analysis_loop,
            args=(app, 1.0),
            daemon=True,
            name="live-packet-llm",
        )
        _state["thread"] = thread
        thread.start()
        router = get_model_router(config)
        status = {
            "enabled": True,
            "session_id": sid,
            "packets_per_min": int(config.get("LLM_LIVE_PACKETS_PER_MIN", 30)),
            "models_per_packet": len(router.stack),
            "model_stack": stack_model_names(config),
        }
        _cache_status(status)
        return {"ok": True, **status, "message": "LLM packet triage started"}

    stop_llm_packet_analysis()
    _cache_status({"enabled": False})
    return {"ok": True, "enabled": False, "message": "LLM packet triage stopped"}


def stop_llm_packet_analysis() -> None:
    stop_event = _state.get("stop_event")
    if stop_event:
        stop_event.set()
    thread = _state.get("thread")
    if thread and thread.is_alive():
        thread.join(timeout=8)
    _state.update({"running": False, "stop_event": None, "thread": None, "heuristics": None})


def llm_packet_analysis_status() -> dict:
    cached = _cache_status()
    running = bool(_state.get("running"))
    thread = _state.get("thread")
    if running and thread and not thread.is_alive():
        running = False
        _state["running"] = False
    stats = dict(_state.get("stats") or {})
    elapsed = 0.0
    if stats.get("started_at"):
        elapsed = round(time.time() - stats["started_at"], 1)
    ctx = list(_state.get("context_log") or [])
    return {
        "enabled": running or bool(cached.get("enabled")),
        "running": running,
        "session_id": _state.get("session_id") or cached.get("session_id"),
        "packets_per_min": cached.get("packets_per_min", 30),
        "models_per_packet": cached.get("models_per_packet", 3),
        "model_stack": cached.get("model_stack") or [],
        "elapsed_sec": elapsed,
        "stats": stats,
        "context_log": ctx[:30],
        "feed_running": packet_feed.feed_status().get("running"),
    }
