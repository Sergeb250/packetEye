"""Live LLM packet triage — sample packet feed, dual-model analysis, emit alerts."""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask

from app.extensions import cache, db
from app.models.analysis import Finding
from app.services.capture import orchestrator as capture_orchestrator
from app.services.detection.scoring import severity_to_score
from app.services.live import packet_feed
from app.services.live.alert_service import AlertService
from app.services.llm.ensemble import _build_secondary
from app.services.llm.provider import get_provider, parse_json_response

logger = logging.getLogger(__name__)

CACHE_KEY = "live:llm_packet_analysis"
PACKET_SYSTEM = (
    "You are a SOC packet triage engine. Classify one network event quickly. "
    "Respond ONLY with valid JSON, no markdown."
)
PACKET_USER = """Network event JSON:
{packet}

Is this suspicious (scan, brute force, C2, exfil, malware, DoS)?
JSON schema:
{{"suspicious": true|false, "severity": "info|medium|high|critical", "confidence": 0.0-1.0, "attack_type": "short label", "summary": "one sentence for analyst"}}"""

_state: dict = {
    "running": False,
    "stop_event": None,
    "thread": None,
    "app": None,
    "session_id": None,
    "stats": {},
}


def _fast_providers(config: dict) -> list[tuple[str, object]]:
    timeout = float(config.get("LLM_LIVE_TIMEOUT_SECONDS", 18))
    max_tok = int(config.get("LLM_LIVE_PACKET_MAX_TOKENS", 320))
    fast = {
        **config,
        "LLM_TIMEOUT_SECONDS": timeout,
        "LLM_MAX_TOKENS": max_tok,
        "LLM_SECONDARY_MAX_TOKENS": max_tok,
    }
    providers: list[tuple[str, object]] = [("primary", get_provider(fast))]
    secondary = _build_secondary(fast)
    if secondary:
        providers.append(("secondary", secondary))
    return providers


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


def _call_model(name: str, provider, packet_json: str) -> tuple[str, dict]:
    user = PACKET_USER.format(packet=packet_json)
    try:
        raw = provider.complete(PACKET_SYSTEM, user, temperature=0.1)
        parsed = parse_json_response(raw or "")
        if parsed:
            parsed["_model"] = name
            return name, parsed
    except Exception as exc:
        logger.debug("Live packet LLM %s failed: %s", name, exc)
    return name, {}


def _merge_verdicts(results: list[dict], min_confidence: float) -> dict | None:
    suspicious = [r for r in results if r.get("suspicious")]
    if not suspicious:
        return None
    best = max(suspicious, key=lambda r: float(r.get("confidence") or 0))
    if float(best.get("confidence") or 0) < min_confidence:
        # Require at least two models to agree when confidence is low
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
    }


def _emit_llm_packet_alert(app: Flask, session_id: str, packet: dict, verdict: dict) -> None:
    with app.app_context():
        config = dict(app.config)
        alerts = AlertService(session_id, ml_strict_c2_filter=False)
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
            "timestamp": time.time(),
            "severity": severity,
            "explanation": summary,
            "attack_type": attack,
            "confidence": conf,
            "models": verdict.get("models"),
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
            title=f"LLM packet triage — {attack}",
            description=summary,
            severity=severity,
            severity_score=severity_to_score(severity),
            evidence={
                "live": True,
                "llm_packet": True,
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


def _resolve_session_id(config: dict, session_id: str | None) -> str | None:
    if session_id:
        return session_id
    sid = capture_orchestrator.get_ml_session_id(config)
    if sid:
        return sid
    from app.services.live.monitor import monitor_status
    from app.models.analysis import Analysis

    latest = Analysis.query.filter_by(source="live").order_by(Analysis.created_at.desc()).first()
    if latest and monitor_status(latest.id).get("running"):
        return latest.id
    return None


def _analysis_loop(app: Flask, poll_sec: float) -> None:
    stop_event: threading.Event = _state["stop_event"]
    session_id = _state["session_id"]
    last_packet_id = 0
    min_conf = float(app.config.get("LLM_LIVE_PACKET_MIN_CONFIDENCE", 0.55))

    with app.app_context():
        config = dict(app.config)
        interval = max(2.0, 60.0 / max(1, int(config.get("LLM_LIVE_PACKETS_PER_MIN", 30))))
        providers = _fast_providers(config)

        while not stop_event.is_set():
            try:
                packets = packet_feed.poll_packets(last_packet_id)
                if not packets:
                    stop_event.wait(poll_sec)
                    continue

                pkt = packets[-1]
                last_packet_id = max(last_packet_id, int(pkt.get("id") or 0))
                packet_json = _compact_packet(pkt)

                results: list[dict] = []
                with ThreadPoolExecutor(max_workers=len(providers)) as pool:
                    futures = {
                        pool.submit(_call_model, name, prov, packet_json): name
                        for name, prov in providers
                    }
                    for fut in as_completed(futures):
                        _, parsed = fut.result()
                        if parsed:
                            results.append(parsed)

                _state["stats"]["packets_analyzed"] = _state["stats"].get("packets_analyzed", 0) + 1
                _state["stats"]["llm_calls"] = _state["stats"].get("llm_calls", 0) + len(providers)
                _state["stats"]["last_packet_at"] = time.time()

                verdict = _merge_verdicts(results, min_conf)
                if verdict:
                    _emit_llm_packet_alert(app, session_id, pkt, verdict)
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
    if enabled and not (config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")):
        return {"ok": False, "error": "No LLM API key configured"}

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
            "stats": {"packets_analyzed": 0, "llm_calls": 0, "alerts_emitted": 0, "started_at": time.time()},
        })
        thread = threading.Thread(
            target=_analysis_loop,
            args=(app, 1.0),
            daemon=True,
            name="live-packet-llm",
        )
        _state["thread"] = thread
        thread.start()
        status = {
            "enabled": True,
            "session_id": sid,
            "packets_per_min": int(config.get("LLM_LIVE_PACKETS_PER_MIN", 30)),
            "models_per_packet": 2 if config.get("LLM_SECONDARY_MODEL") else 1,
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
    _state.update({"running": False, "stop_event": None, "thread": None})


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
    return {
        "enabled": running or bool(cached.get("enabled")),
        "running": running,
        "session_id": _state.get("session_id") or cached.get("session_id"),
        "packets_per_min": cached.get("packets_per_min", 30),
        "models_per_packet": cached.get("models_per_packet", 2),
        "elapsed_sec": elapsed,
        "stats": stats,
        "feed_running": packet_feed.feed_status().get("running"),
    }
