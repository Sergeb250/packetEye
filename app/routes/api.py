import csv
import io
import json
import os
import uuid
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, render_template
from werkzeug.utils import secure_filename

from app.extensions import db, limiter
from app.models.analysis import Analysis, Finding, Flow, Observable
from app.services.pcap_parser import validate_pcap_magic
from app.services.analysis_runner import kickoff_analysis_current
from app.services.live_runner import kickoff_live_monitor_current
from app.services.ml_dashboard import build_live_monitor_context
from app.tasks.live_tasks import create_live_session, stop_live_monitor_task
from app.services.live.alert_service import AlertService
from app.services.live.monitor import monitor_status, stop_monitor, rebind_eve
from app.services.live.live_packet_llm import (
    llm_packet_analysis_status,
    set_llm_packet_analysis,
    stop_llm_packet_analysis,
)
from app.services.live.triage_registry import (
    get_incident,
    list_incidents,
    set_verdict,
    summary_stats,
    update_incident,
)
from app.services.live.triage_inspector import deep_inspect_incident
from app.services.llm.connectivity import probe_llm_connectivity
from app.services.llm.suricata_rule_writer import generate_suricata_rules
from app.services.live import suricata_manager
from app.services.live.webhook_notifier import WebhookNotifier
from app.services.capture import orchestrator as capture_orchestrator
from app.services.capture import ml_capture
from app.services.capture import pcap_watcher
from app.services.live import packet_feed
from app.services.investigation.service import (
    get_flow_investigation,
    get_investigation,
    investigate_flow_sync,
    investigate_target_sync,
    kickoff_investigation,
    refresh_analysis_metrics,
)
from app.services.llm import chat as soc_chat
from app.services.ml_dashboard import build_dashboard_context

api_bp = Blueprint("api", __name__)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


def _allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


@api_bp.route("/upload", methods=["POST"])
@limiter.limit("10 per hour")
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    if not _allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Accepted: .pcap, .pcapng, .cap"}), 400

    upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
    upload_dir.mkdir(parents=True, exist_ok=True)

    analysis_id = str(uuid.uuid4())
    ext = Path(file.filename).suffix.lower()
    stored_name = f"{analysis_id}{ext}"
    file_path = upload_dir / stored_name
    file.save(str(file_path))

    if not validate_pcap_magic(str(file_path)):
        file_path.unlink(missing_ok=True)
        return jsonify({"error": "File is not a valid PCAP capture (magic byte check failed)"}), 400

    analysis = Analysis(
        id=analysis_id,
        filename=secure_filename(file.filename),
        file_path=str(file_path),
        analysis_name=request.form.get("analysis_name"),
        analyst_notes=request.form.get("analyst_notes"),
        status="queued",
        progress_pct=0,
        summary_json={"progress_message": "Upload complete — starting analysis pipeline..."},
    )
    db.session.add(analysis)
    db.session.commit()

    kickoff_analysis_current(analysis_id)

    return jsonify({"analysis_id": analysis_id, "status": "queued"}), 201


@limiter.exempt
@api_bp.route("/analysis/<analysis_id>/status")
def analysis_status(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    return jsonify(analysis.to_dict())


@api_bp.route("/analysis/<analysis_id>/summary")
def analysis_summary(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    return jsonify(
        {
            **analysis.to_dict(),
            "summary": analysis.summary_json or {},
            "report": analysis.report_json or {},
        }
    )


@api_bp.route("/analysis/<analysis_id>/findings")
def analysis_findings(analysis_id):
    Analysis.query.get_or_404(analysis_id)
    severity = request.args.get("severity")
    source = request.args.get("source")
    q = Finding.query.filter_by(analysis_id=analysis_id)
    if severity:
        q = q.filter_by(severity=severity)
    if source:
        q = q.filter_by(source=source)
    findings = q.order_by(Finding.severity_score.desc()).all()
    return jsonify([f.to_dict() for f in findings])


@api_bp.route("/analysis/<analysis_id>/flows")
def analysis_flows(analysis_id):
    Analysis.query.get_or_404(analysis_id)
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    protocol = request.args.get("protocol")
    flagged_only = request.args.get("flagged") == "true"
    external_only = request.args.get("external") == "true"

    q = Flow.query.filter_by(analysis_id=analysis_id)
    if protocol:
        q = q.filter_by(protocol=protocol)
    if flagged_only:
        q = q.filter(Flow.severity_score > 0)
    if external_only:
        q = q.filter(Flow.is_whitelisted == False)  # noqa: E712

    pagination = q.order_by(Flow.severity_score.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify(
        {
            "flows": [f.to_dict() for f in pagination.items],
            "total": pagination.total,
            "page": page,
            "per_page": per_page,
            "pages": pagination.pages,
        }
    )


@api_bp.route("/analysis/<analysis_id>/observables")
def analysis_observables(analysis_id):
    Analysis.query.get_or_404(analysis_id)
    obs_type = request.args.get("type")
    q = Observable.query.filter_by(analysis_id=analysis_id)
    if obs_type:
        q = q.filter_by(type=obs_type)
    return jsonify([o.to_dict() for o in q.all()])


@api_bp.route("/analysis/<analysis_id>/report.json")
def report_json(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    return jsonify(analysis.report_json or {})


@api_bp.route("/analysis/<analysis_id>/report.html")
def report_html(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    findings = Finding.query.filter_by(analysis_id=analysis_id).all()
    return render_template(
        "report_export.html",
        analysis=analysis,
        report=analysis.report_json or {},
        findings=findings,
    )


@api_bp.route("/analysis/<analysis_id>/stix2.json")
def report_stix2(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    findings = Finding.query.filter_by(analysis_id=analysis_id, is_false_positive=False).all()
    try:
        from stix2 import Bundle, Indicator

        indicators = []
        for f in findings:
            indicators.append(
                Indicator(
                    name=f.title,
                    description=f.description or f.title,
                    pattern="[network-traffic:src_ref.value = 'placeholder']",
                    pattern_type="stix",
                    valid_from=analysis.created_at.isoformat() if analysis.created_at else "2026-01-01T00:00:00Z",
                    labels=[f.severity],
                )
            )
        bundle = Bundle(objects=indicators)
        return jsonify(json.loads(bundle.serialize()))
    except ImportError:
        return jsonify({"type": "bundle", "objects": [f.to_dict() for f in findings]})


@api_bp.route("/analysis/<analysis_id>/export.csv")
def export_csv(analysis_id):
    Analysis.query.get_or_404(analysis_id)
    flows = Flow.query.filter_by(analysis_id=analysis_id).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes_sent", "bytes_recv", "duration_ms", "app_layer", "severity"]
    )
    for f in flows:
        writer.writerow(
            [f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol, f.bytes_sent, f.bytes_recv, f.duration_ms, f.application_layer, f.severity_score]
        )
    from flask import Response

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=flows_{analysis_id}.csv"},
    )


@api_bp.route("/analysis/<analysis_id>", methods=["DELETE"])
def delete_analysis(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    try:
        if analysis.file_path and os.path.exists(analysis.file_path):
            os.remove(analysis.file_path)
    except OSError:
        pass
    db.session.delete(analysis)
    db.session.commit()
    return jsonify({"deleted": True})


@api_bp.route("/analysis/<analysis_id>/feedback", methods=["POST"])
def feedback(analysis_id):
    data = request.get_json() or {}
    finding_id = data.get("finding_id")
    is_fp = data.get("is_false_positive", False)
    finding = Finding.query.filter_by(id=finding_id, analysis_id=analysis_id).first_or_404()
    finding.is_false_positive = is_fp
    db.session.commit()
    return jsonify({"finding_id": finding_id, "is_false_positive": is_fp})


@api_bp.route("/health")
def health():
    config = current_app.config
    ml_model = Path(config.get("ML_MODEL_PATH", ""))
    ml_scaler = Path(config.get("ML_SCALER_PATH", ""))
    benchmark_path = ml_model.parent / "benchmark_results.json"
    benchmark = {}
    if benchmark_path.exists():
        try:
            benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return jsonify(
        {
            "status": "ok",
            "llm_enabled": config.get("LLM_ENABLED"),
            "llm_provider": config.get("LLM_PROVIDER"),
            "llm_model": config.get("LLM_MODEL"),
            "llm_configured": bool(
                config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")
            ),
            "nvidia_configured": bool(config.get("NVIDIA_API_KEY") or config.get("LLM_API_KEY")),
            "zai_configured": bool(config.get("ZAI_API_KEY")),
            "zai_model": config.get("ZAI_MODEL"),
            "virustotal_configured": bool(config.get("VIRUSTOTAL_API_KEY")),
            "abuseipdb_configured": bool(config.get("ABUSEIPDB_API_KEY")),
            "ml_baseline_loaded": ml_model.exists() and ml_scaler.exists(),
            "live_monitor_enabled": config.get("LIVE_MONITOR_ENABLED"),
            "benchmark_summary": benchmark.get("summary"),
        }
    )


@api_bp.route("/live/config")
def live_config():
    cfg = dict(current_app.config)
    return jsonify(build_live_monitor_context(cfg))


@api_bp.route("/live/start", methods=["POST"])
@limiter.limit("10 per hour")
def live_start():
    if not current_app.config.get("LIVE_MONITOR_ENABLED"):
        return jsonify({"error": "Live monitor disabled. Set LIVE_MONITOR_ENABLED=true in .env"}), 403

    config = dict(current_app.config)
    data = request.get_json() or {}
    mode = (data.get("mode") or str(config.get("CAPTURE_MODE") or "suricata")).strip().lower()
    interface = (data.get("interface") or "").strip() or None
    auto_capture = data.get("auto_start_capture")
    if auto_capture is None:
        auto_capture = mode == "suricata"
    else:
        auto_capture = bool(auto_capture)
    capture_started = False

    # tcpdump: rotating PCAP chunks + live ML from Scapy packet feed
    if mode == "tcpdump":
        iface = interface or config.get("CAPTURE_INTERFACE") or config.get("SURICATA_INTERFACE") or "eth0"
        cap_status = capture_orchestrator.capture_status(config)
        if not cap_status.get("running"):
            result = capture_orchestrator.start_capture(config, mode="tcpdump", interface=iface)
            if not result.get("ok"):
                err = {"error": result.get("error")}
                if result.get("hint"):
                    err["hint"] = result["hint"]
                return jsonify(err), 400
            if result.get("chunk_dir"):
                config["TCPDUMP_CHUNK_DIR"] = result["chunk_dir"]
        else:
            result = {
                "ok": True,
                "pid": cap_status.get("pid"),
                "interface": cap_status.get("interface") or iface,
            }
            iface = result["interface"]

        pcap_watcher.start_watcher(current_app._get_current_object())
        packet_feed.start_feed(config, "tcpdump", iface)
        ml = ml_capture.attach_ml_to_capture(config, "tcpdump", iface)

        return jsonify(
            {
                "mode": "tcpdump",
                "status": "capturing",
                "pid": result.get("pid"),
                "chunk_dir": config.get("TCPDUMP_CHUNK_DIR"),
                "session_id": ml.get("session_id"),
                "ml_status": ml.get("status"),
                "interface": iface,
                "note": "Live ML scores Scapy flows; closed chunks also appear under Analyses.",
            }
        ), 201

    raw_eve = (data.get("eve_path") or "").strip() or config.get("SURICATA_EVE_PATH", "")
    if not raw_eve.strip():
        log_dir = str(config.get("SURICATA_LOG_DIR") or "").strip()
        if log_dir:
            raw_eve = str(Path(log_dir) / "eve.json")

    if mode == "suricata" and auto_capture:
        status = capture_orchestrator.capture_status(config)
        if not status.get("running"):
            result = capture_orchestrator.start_capture(config, mode="suricata", interface=interface)
            if not result.get("ok"):
                return jsonify({"error": result.get("error")}), 400
            capture_started = True
            if result.get("eve_hint"):
                raw_eve = result["eve_hint"]
        elif status.get("suricata", {}).get("eve", {}).get("path"):
            raw_eve = status["suricata"]["eve"]["path"]

    eve_path = str(Path(raw_eve).expanduser().resolve()) if raw_eve else ""
    if not eve_path:
        return jsonify({"error": "EVE log path is required. Paste the full path to your eve.json file."}), 400

    # If we just launched Suricata, the EVE file may take a moment to appear —
    # the consumer polls until it exists.
    if not capture_started and not Path(eve_path).is_file():
        cap_status = capture_orchestrator.capture_status(config)
        sur_status = suricata_manager.get_status(config)
        if not cap_status.get("running") and not sur_status.get("running"):
            return jsonify(
                {
                    "error": f"EVE log not found: {eve_path}",
                    "hint": "Start Suricata capture first (Capture page), or run packetEye as root: sudo python run.py",
                }
            ), 400

    if not Path(config.get("ML_MODEL_PATH", "")).is_file():
        return jsonify({"error": "ML baseline model not loaded. Run scripts/train_tracker.py first."}), 400

    analysis = create_live_session(config, eve_path=eve_path, interface=interface)
    kickoff_live_monitor_current(analysis.id)

    return jsonify(
        {
            "session_id": analysis.id,
            "status": "running",
            "mode": "suricata",
            "capture_started": capture_started,
            "eve_path": eve_path,
            "interface": interface,
        }
    ), 201


@api_bp.route("/live/stop", methods=["POST"])
def live_stop():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"error": "session_id required"}), 400

    stop_monitor(session_id)
    stop_llm_packet_analysis()
    stop_live_monitor_task.delay(session_id)

    analysis = Analysis.query.get(session_id)
    if analysis:
        analysis.status = "complete"
        db.session.commit()

    return jsonify({"session_id": session_id, "status": "stopped"})


@api_bp.route("/live/rebind-eve", methods=["POST"])
@limiter.limit("30 per hour")
def live_rebind_eve():
    data = request.get_json() or {}
    session_id = data.get("session_id") or request.args.get("session_id")
    eve_path = (data.get("eve_path") or "").strip()
    if not session_id or not eve_path:
        return jsonify({"error": "session_id and eve_path required"}), 400
    path = Path(eve_path).expanduser()
    if not path.is_file():
        return jsonify({"error": f"EVE file not found: {path}"}), 400
    if not rebind_eve(session_id, str(path.resolve())):
        return jsonify({"error": "Session not found"}), 404
    from app.services.live import packet_feed
    packet_feed.rebind_eve(str(path.resolve()))
    return jsonify({"ok": True, "session_id": session_id, "eve_path": str(path.resolve())})


@api_bp.route("/live/import-eve", methods=["POST"])
@limiter.limit("10 per hour")
def live_import_eve():
    config = dict(current_app.config)
    max_bytes = int(config.get("EVE_IMPORT_MAX_MB", 100)) * 1024 * 1024
    import_dir = Path(config.get("UPLOAD_FOLDER", "data/uploads")).parent / "imports"
    import_dir.mkdir(parents=True, exist_ok=True)

    if request.files.get("file"):
        f = request.files["file"]
        if f.content_length and f.content_length > max_bytes:
            return jsonify({"error": "File too large"}), 400
        dest = import_dir / f"eve_{int(__import__('time').time())}.json"
        f.save(dest)
        eve_path = str(dest.resolve())
    else:
        data = request.get_json() or {}
        raw_path = (data.get("eve_path") or "").strip()
        if not raw_path:
            return jsonify({"error": "file or eve_path required"}), 400
        src = Path(raw_path).expanduser()
        if not src.is_file():
            return jsonify({"error": f"File not found: {src}"}), 400
        if src.stat().st_size > max_bytes:
            return jsonify({"error": "File too large"}), 400
        dest = import_dir / f"eve_{int(__import__('time').time())}.json"
        dest.write_bytes(src.read_bytes())
        eve_path = str(dest.resolve())

    return jsonify({"ok": True, "eve_path": eve_path}), 201


@limiter.exempt
@api_bp.route("/live/status")
def live_status():
    session_id = request.args.get("session_id")
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
    return jsonify(monitor_status(session_id))


@limiter.exempt
@api_bp.route("/live/alerts")
def live_alerts():
    session_id = request.args.get("session_id")
    since = request.args.get("since", 0, type=float)
    severity_q = (request.args.get("severity") or "").strip().lower()
    source_q = (request.args.get("source") or "").strip().lower()
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
    alerts = AlertService.get_alerts(session_id, since_ts=since)
    if severity_q:
        allowed = {s.strip() for s in severity_q.split(",") if s.strip()}
        alerts = [a for a in alerts if (a.get("severity") or "").lower() in allowed]
    if source_q:
        allowed = {s.strip() for s in source_q.split(",") if s.strip()}
        alerts = [a for a in alerts if (a.get("type") or "").lower() in allowed]
    return jsonify({"alerts": alerts, "count": len(alerts)})


@api_bp.route("/llm/test", methods=["POST"])
@limiter.limit("20 per hour")
def llm_test():
    result = probe_llm_connectivity(dict(current_app.config))
    status = 200 if result.get("ok") else 503
    return jsonify(result), status


@api_bp.route("/live/llm-packets", methods=["GET", "POST"])
@limiter.limit("30 per hour")
def live_llm_packets():
    if request.method == "GET":
        return jsonify(llm_packet_analysis_status())

    data = request.get_json() or {}
    enabled = data.get("enabled")
    if enabled is None:
        return jsonify({"error": "enabled (true/false) required"}), 400
    result = set_llm_packet_analysis(
        current_app._get_current_object(),
        enabled=bool(enabled),
        session_id=data.get("session_id"),
    )
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@limiter.exempt
@api_bp.route("/live/triage/incidents")
def live_triage_incidents():
    session_id = request.args.get("session_id")
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
    since = request.args.get("since", 0, type=float)
    disposition = (request.args.get("disposition") or "").strip() or None
    source = (request.args.get("source") or "").strip() or None
    search = (request.args.get("search") or "").strip() or None
    limit = min(500, request.args.get("limit", 200, type=int))
    rows = list_incidents(
        session_id,
        since_ts=since,
        disposition=disposition,
        source=source,
        search=search,
        limit=limit,
    )
    return jsonify({"incidents": rows, "count": len(rows)})


@api_bp.route("/live/triage/inspect", methods=["POST"])
@limiter.limit("30 per hour")
def live_triage_inspect():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    incident_id = data.get("incident_id")
    if not session_id or not incident_id:
        return jsonify({"error": "session_id and incident_id required"}), 400
    row = get_incident(session_id, incident_id)
    if not row:
        return jsonify({"error": "Incident not found"}), 404
    result = deep_inspect_incident(dict(current_app.config), row)
    if result.get("ok"):
        update_incident(session_id, incident_id, {"deep_inspect": result})
    status = 200 if result.get("ok") else 503
    return jsonify(result), status


@api_bp.route("/live/triage/verdict", methods=["POST"])
@limiter.limit("60 per hour")
def live_triage_verdict():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    incident_id = data.get("incident_id")
    disposition = (data.get("disposition") or "").strip()
    if not session_id or not incident_id or not disposition:
        return jsonify({"error": "session_id, incident_id, and disposition required"}), 400
    row = set_verdict(
        session_id,
        incident_id,
        disposition,
        analyst_note=(data.get("note") or "").strip(),
    )
    if not row:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify({"ok": True, "incident": row})


@limiter.exempt
@api_bp.route("/live/triage/status")
def live_triage_status():
    session_id = request.args.get("session_id")
    llm = llm_packet_analysis_status()
    stats = summary_stats(session_id) if session_id else {"total": 0, "by_disposition": {}, "by_source": {}}
    return jsonify({"llm_packet_triage": llm, "registry": stats})


@api_bp.route("/suricata/rules/generate", methods=["POST"])
@limiter.limit("20 per hour")
def suricata_rules_generate():
    data = request.get_json() or {}
    description = (data.get("description") or "").strip()
    existing = data.get("existing_content")
    if existing is None:
        read = suricata_manager.read_rules(dict(current_app.config))
        existing = read.get("content") if read.get("ok") else ""
    result = generate_suricata_rules(dict(current_app.config), description, existing or "")
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@api_bp.route("/suricata/rules/test", methods=["POST"])
@limiter.limit("30 per hour")
def suricata_rules_test():
    data = request.get_json() or {}
    content = data.get("content")
    if content is None:
        return jsonify({"error": "content field required"}), 400
    iface = (data.get("interface") or "").strip()
    result = suricata_manager.test_rules_draft(dict(current_app.config), str(content), iface)
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


def _geo_markers_for(observables, analysis_name=None) -> list:
    markers = []
    for obs in observables:
        if obs.type != "ip":
            continue
        geo = (obs.enrichment_json or {}).get("geo", {})
        if not (geo.get("lat") and geo.get("lon")):
            continue
        markers.append(
            {
                "ip": obs.value,
                "lat": geo["lat"],
                "lon": geo["lon"],
                "country": geo.get("country"),
                "city": geo.get("city"),
                "is_malicious": bool(obs.is_malicious),
                "confidence": obs.confidence or 0,
                "analysis": analysis_name,
            }
        )
    return markers


@limiter.exempt
@api_bp.route("/analysis/<analysis_id>/geo")
def analysis_geo(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    observables = Observable.query.filter_by(analysis_id=analysis_id).all()
    return jsonify({"markers": _geo_markers_for(observables, analysis.analysis_name)})


@limiter.exempt
@api_bp.route("/dashboard/threat_map")
def dashboard_threat_map():
    recent = Analysis.query.order_by(Analysis.created_at.desc()).limit(20).all()
    markers = []
    for analysis in recent:
        observables = Observable.query.filter_by(analysis_id=analysis.id).limit(200).all()
        markers.extend(_geo_markers_for(observables, analysis.analysis_name or analysis.filename))
        if len(markers) >= 400:
            break
    return jsonify({"markers": markers[:400]})


@limiter.exempt
@api_bp.route("/capture/status")
def capture_status():
    config = dict(current_app.config)
    status = capture_orchestrator.capture_status(config)
    status["chunk_watcher"] = pcap_watcher.watcher_status()
    feed = packet_feed.feed_status()
    if status.get("running") and not feed.get("running"):
        packet_feed.start_feed(
            config,
            mode=status.get("mode") or "suricata",
            interface=status.get("interface") or "",
            eve_path=(status.get("suricata") or {}).get("eve", {}).get("path"),
        )
        feed = packet_feed.feed_status()
    status["live_feed"] = feed
    return jsonify(status)


@limiter.exempt
@api_bp.route("/capture/packets")
def capture_packets():
    since = request.args.get("since", 0, type=int)
    return jsonify(
        {
            "packets": packet_feed.poll_packets(since),
            "status": packet_feed.feed_status(),
        }
    )


@api_bp.route("/capture/packets/clear", methods=["POST"])
@limiter.limit("60 per hour")
def capture_packets_clear():
    packet_feed.clear_feed()
    return jsonify({"ok": True})


@api_bp.route("/capture/start", methods=["POST"])
@limiter.limit("10 per hour")
def capture_start():
    if not current_app.config.get("LIVE_MONITOR_ENABLED"):
        return jsonify({"error": "Live monitor disabled. Set LIVE_MONITOR_ENABLED=true in .env"}), 403
    data = request.get_json() or {}
    result = capture_orchestrator.start_capture(
        dict(current_app.config),
        mode=data.get("mode"),
        interface=data.get("interface"),
    )
    if not result.get("ok"):
        err = {"error": result.get("error")}
        if result.get("hint"):
            err["hint"] = result["hint"]
        return jsonify(err), 400
    if result.get("chunk_dir"):
        current_app.config["TCPDUMP_CHUNK_DIR"] = result["chunk_dir"]
    mode = result.get("mode") or "suricata"
    iface = result.get("interface") or data.get("interface") or ""
    if mode == "tcpdump":
        pcap_watcher.start_watcher(current_app._get_current_object())
    packet_feed.start_feed(
        dict(current_app.config),
        mode=mode,
        interface=iface,
        eve_path=result.get("eve_hint"),
    )
    ml = ml_capture.attach_ml_to_capture(
        dict(current_app.config),
        mode,
        iface,
        eve_hint=result.get("eve_hint"),
    )
    result["session_id"] = ml.get("session_id")
    result["ml_status"] = ml.get("status")
    return jsonify(result), 201


@api_bp.route("/capture/stop", methods=["POST"])
@limiter.limit("20 per hour")
def capture_stop():
    config = dict(current_app.config)
    ml_result = ml_capture.stop_ml_for_capture(config)
    packet_feed.stop_feed()
    result = capture_orchestrator.stop_capture(config)
    pcap_watcher.stop_watcher()
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 400
    result["ml_stopped"] = ml_result.get("stopped", False)
    if ml_result.get("session_id"):
        result["ml_session_id"] = ml_result["session_id"]
    return jsonify(result)


@api_bp.route("/investigate/finding/<finding_id>", methods=["POST"])
@limiter.limit("30 per hour")
def investigate_finding(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    existing = (finding.evidence or {}).get("investigation") or {}
    if existing.get("status") == "running":
        return jsonify({"status": "running", "finding_id": finding_id}), 202
    kickoff_investigation(current_app._get_current_object(), finding_id)
    return jsonify({"status": "started", "finding_id": finding_id}), 202


@limiter.exempt
@api_bp.route("/investigate/finding/<finding_id>", methods=["GET"])
def investigation_result(finding_id):
    result = get_investigation(finding_id)
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 404
    return jsonify(result)


@api_bp.route("/investigate/flow/<flow_id>", methods=["POST"])
@limiter.limit("30 per hour")
def investigate_flow(flow_id):
    result = investigate_flow_sync(dict(current_app.config), flow_id)
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 400
    return jsonify(result), 202 if result.get("investigation", {}).get("status") == "running" else 200


@limiter.exempt
@api_bp.route("/investigate/flow/<flow_id>", methods=["GET"])
def investigation_flow_result(flow_id):
    result = get_flow_investigation(flow_id)
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 404
    return jsonify(result)


@api_bp.route("/investigate/target/<analysis_id>/<path:target>", methods=["GET", "POST"])
@limiter.limit("60 per hour")
def investigate_target(analysis_id, target):
    Analysis.query.get_or_404(analysis_id)
    target = target.strip()
    target_type = "domain"
    try:
        import ipaddress
        ipaddress.ip_address(target)
        target_type = "ip"
    except ValueError:
        if "." not in target:
            return jsonify({"error": "Invalid target"}), 400

    summarize_param = (request.args.get("summarize") or "").strip().lower()
    detail_level = (request.args.get("detail") or request.args.get("detail_level") or "medium").strip().lower()
    if detail_level not in ("brief", "medium", "detailed"):
        detail_level = "medium"
    alert_context = None
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        alert_context = body.get("alert_context")
        if body.get("detail_level"):
            detail_level = str(body.get("detail_level")).lower()
        if body.get("summarize") is False:
            summarize = False
        elif body.get("summarize"):
            summarize = True
        else:
            summarize = summarize_param not in ("0", "false", "no")
    else:
        summarize = summarize_param not in ("0", "false", "no") if summarize_param else True

    result = investigate_target_sync(
        dict(current_app.config),
        analysis_id,
        target_type,
        target,
        summarize=summarize,
        alert_context=alert_context,
        detail_level=detail_level,
    )
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 400
    return jsonify(result)


@limiter.exempt
@api_bp.route("/analysis/<analysis_id>/metrics")
def analysis_metrics(analysis_id):
    result = refresh_analysis_metrics(analysis_id)
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 404
    return jsonify(result)


@api_bp.route("/analysis/<analysis_id>/refresh-report", methods=["POST"])
@limiter.limit("20 per hour")
def refresh_report_metrics(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    metrics = refresh_analysis_metrics(analysis_id)
    report = dict(analysis.report_json or {})
    report["risk_score"] = metrics["risk_score"]
    report.setdefault("metrics", {})
    report["metrics"]["malicious_observables"] = metrics["malicious_observables"]
    report["metrics"]["investigated_count"] = metrics["investigated_count"]
    analysis.report_json = report
    analysis.risk_score = metrics["risk_score"]
    db.session.commit()
    return jsonify({"ok": True, "metrics": metrics})


@api_bp.route("/chat", methods=["POST"])
@limiter.limit("60 per hour")
def chat():
    if not current_app.config.get("CHATBOT_ENABLED", True):
        return jsonify({"error": "Chatbot disabled (CHATBOT_ENABLED=false)."}), 403
    data = request.get_json() or {}
    result = soc_chat.chat(
        dict(current_app.config),
        message=data.get("message", ""),
        history=data.get("history") or [],
        analysis_id=data.get("analysis_id"),
        finding_id=data.get("finding_id"),
        flow_id=data.get("flow_id"),
        context_payload=data.get("context_payload"),
    )
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 400
    return jsonify({"reply": result["reply"]})


@api_bp.route("/webhook/test", methods=["POST"])
@limiter.limit("10 per hour")
def webhook_test():
    result = WebhookNotifier(dict(current_app.config)).send_test()
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 400
    return jsonify({"ok": True, "message": "Test alert sent to the configured webhook."})


@limiter.exempt
@api_bp.route("/suricata/status")
def suricata_status():
    config = dict(current_app.config)
    status = suricata_manager.get_status(config)
    diag = suricata_manager.get_diagnostics(config)
    status["diagnostics_count"] = len(diag.get("rows") or [])
    return jsonify(status)


@limiter.exempt
@api_bp.route("/suricata/diagnostics")
def suricata_diagnostics():
    return jsonify(suricata_manager.get_diagnostics(dict(current_app.config)))


@limiter.exempt
@api_bp.route("/suricata/monitor")
def suricata_monitor():
    since = request.args.get("since", 0, type=int)
    config = dict(current_app.config)
    return jsonify(
        {
            "events": suricata_manager.poll_monitor_events(config, since_id=since),
            "status": suricata_manager.get_status(config),
        }
    )


@limiter.exempt
@api_bp.route("/suricata/export")
def suricata_export():
    import csv
    import io

    since = request.args.get("since", 0, type=int)
    fmt = (request.args.get("format") or "json").lower()
    config = dict(current_app.config)
    events = suricata_manager.poll_monitor_events(config, since_id=since)
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol", "length", "info", "severity", "event_type",
        ])
        writer.writeheader()
        for ev in events:
            writer.writerow({k: ev.get(k) for k in writer.fieldnames})
        return buf.getvalue(), 200, {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=suricata_eve.csv"}
    return jsonify({"events": events, "count": len(events)})


@limiter.exempt
@api_bp.route("/capture/export-packets")
def capture_export_packets():
    import csv
    import io

    from app.services.live import packet_feed

    fmt = (request.args.get("format") or "json").lower()
    since = request.args.get("since", 0, type=int)
    rows = packet_feed.poll_packets(since)
    if fmt == "csv":
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        return buf.getvalue(), 200, {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=capture_packets.csv"}
    return jsonify({"packets": rows, "count": len(rows)})


@limiter.exempt
@api_bp.route("/capture/download-chunks")
def capture_download_chunks():
    from app.services.capture.orchestrator import capture_status, list_tcpdump_chunks

    config = dict(current_app.config)
    status = capture_status(config)
    chunks = list_tcpdump_chunks(config)
    return jsonify({"mode": status.get("mode"), "chunks": chunks})


@api_bp.route("/suricata/preflight", methods=["POST"])
@limiter.limit("30 per hour")
def suricata_preflight():
    data = request.get_json() or {}
    result = suricata_manager.run_preflight(dict(current_app.config), interface=data.get("interface"))
    code = 200 if result.get("ok") else 400
    return jsonify(result), code


@api_bp.route("/suricata/interfaces")
def suricata_interfaces():
    return jsonify({"interfaces": suricata_manager.list_interfaces()})


@api_bp.route("/suricata/start", methods=["POST"])
@limiter.limit("10 per hour")
def suricata_start():
    if not current_app.config.get("LIVE_MONITOR_ENABLED"):
        return jsonify({"error": "Live monitor disabled. Set LIVE_MONITOR_ENABLED=true in .env"}), 403
    data = request.get_json() or {}
    result = suricata_manager.start_suricata(
        dict(current_app.config), interface=data.get("interface")
    )
    if not result.get("ok"):
        payload = {k: v for k, v in result.items() if v is not None}
        payload.setdefault("error", "Failed to start Suricata")
        return jsonify(payload), 400
    return jsonify(result), 201


@api_bp.route("/suricata/stop", methods=["POST"])
@limiter.limit("10 per hour")
def suricata_stop():
    result = suricata_manager.stop_suricata()
    if not result.get("ok"):
        return jsonify({"error": result.get("error", "Failed to stop Suricata")}), 400
    return jsonify(result)


@api_bp.route("/suricata/rules", methods=["GET"])
def suricata_rules_get():
    result = suricata_manager.read_rules(dict(current_app.config))
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 400
    return jsonify(result)


@api_bp.route("/suricata/rules", methods=["POST"])
@limiter.limit("30 per hour")
def suricata_rules_save():
    data = request.get_json() or {}
    content = data.get("content")
    if content is None:
        return jsonify({"error": "content field required"}), 400
    result = suricata_manager.write_rules(dict(current_app.config), str(content))
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 400
    return jsonify(result)


@api_bp.route("/ml/benchmark")
def ml_benchmark():
    path = Path(current_app.config.get("ML_MODEL_PATH", "")).parent / "benchmark_results.json"
    if not path.exists():
        return jsonify({"error": "No benchmark results. Run scripts/evaluate_model.py"}), 404
    return jsonify(json.loads(path.read_text(encoding="utf-8")))


from app.services.lab.patterns import ALL_LAB_PATTERNS


def _parse_patterns(data: dict) -> list[str] | None:
    raw = data.get("patterns")
    if raw is None:
        return None
    if isinstance(raw, str):
        if raw.strip().lower() == "all":
            return None
        return [p.strip() for p in raw.split(",") if p.strip()]
    if isinstance(raw, list) and (not raw or (len(raw) == 1 and str(raw[0]).lower() == "all")):
        return None
    return raw


@api_bp.route("/lab/start", methods=["POST"])
@limiter.limit("20 per hour")
def lab_start():
    if not current_app.config.get("CAPTURE_LAB_ENABLED"):
        return jsonify({
            "error": "Lab traffic disabled. Set CAPTURE_LAB_ENABLED=true in .env (sensor/lab only).",
        }), 403
    from app.config import BASE_DIR
    from app.services.lab import traffic_runner

    data = request.get_json() or {}
    patterns = _parse_patterns(data)
    rotate_sec = int(data.get("rotate_sec") or current_app.config.get("LAB_ROTATE_SEC") or 12)
    iface = (data.get("interface") or "").strip() or current_app.config.get("CAPTURE_INTERFACE") or "eth0"
    script = BASE_DIR / "scripts" / "generate_test_traffic.py"
    result = traffic_runner.start_lab_traffic(script, patterns, iface, rotate_sec=rotate_sec)
    if not result.get("ok"):
        return jsonify({"error": result.get("error")}), 400
    return jsonify(result), 201


@api_bp.route("/lab/stop", methods=["POST"])
@limiter.limit("30 per hour")
def lab_stop():
    from app.services.lab import traffic_runner

    return jsonify(traffic_runner.stop_lab_traffic())


@limiter.exempt
@api_bp.route("/lab/status")
def lab_status_route():
    from app.services.lab import traffic_runner

    return jsonify(traffic_runner.lab_status())


@api_bp.route("/lab/generate-traffic", methods=["POST"])
@limiter.limit("5 per hour")
def lab_generate_traffic():
    """One-shot lab run (legacy). Prefer /api/lab/start for start/stop + live log."""
    if not current_app.config.get("CAPTURE_LAB_ENABLED"):
        return jsonify({
            "error": "Lab traffic disabled. Set CAPTURE_LAB_ENABLED=true in .env (sensor/lab only).",
        }), 403
    import subprocess
    import sys

    from app.config import BASE_DIR

    data = request.get_json() or {}
    patterns = _parse_patterns(data) or list(ALL_LAB_PATTERNS)
    iface = (data.get("interface") or "").strip() or current_app.config.get("CAPTURE_INTERFACE") or "eth0"
    duration = int(data.get("duration_sec") or 30)
    script = BASE_DIR / "scripts" / "generate_test_traffic.py"
    if not script.is_file():
        return jsonify({"error": "scripts/generate_test_traffic.py not found"}), 500
    cmd = [
        sys.executable,
        str(script),
        "--interface", iface,
        "--duration", str(duration),
        "--pattern", ",".join(patterns),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 60, cwd=str(script.parent.parent))
        log = (proc.stdout or "") + (proc.stderr or "")
        return jsonify({
            "ok": proc.returncode == 0,
            "log": log[-4000:] or f"exit {proc.returncode}",
            "patterns": patterns,
            "interface": iface,
        }), 200 if proc.returncode == 0 else 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Lab traffic generator timed out"}), 504
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/nids-test/start", methods=["POST"])
@limiter.limit("10 per hour")
def nids_test_start():
    """Start long-running NIDS + ML soak test (capture, optional lab traffic, alert polling)."""
    from app.services.lab import nids_test_runner

    config = dict(current_app.config)
    data = request.get_json() or {}
    patterns = _parse_patterns(data)
    auto_capture = data.get("auto_capture")
    if auto_capture is not None:
        auto_capture = bool(auto_capture)
    rotate_sec = int(data.get("rotate_sec") or config.get("LAB_ROTATE_SEC") or 12)
    result = nids_test_runner.start_nids_soak(
        current_app._get_current_object(),
        config,
        mode=(data.get("mode") or "").strip() or None,
        interface=(data.get("interface") or "").strip() or None,
        eve_path=(data.get("eve_path") or "").strip() or None,
        with_lab=bool(data.get("with_lab", True)),
        patterns=patterns,
        auto_capture=auto_capture,
        poll_sec=float(data.get("poll_sec") or 5),
        rotate_sec=rotate_sec,
        stop_live_on_exit=bool(data.get("stop_live_on_exit", True)),
    )
    if not result.get("ok"):
        code = 403 if "disabled" in str(result.get("error", "")).lower() else 400
        return jsonify(result), code
    return jsonify(result), 201


@api_bp.route("/nids-test/stop", methods=["POST"])
@limiter.limit("30 per hour")
def nids_test_stop():
    from app.services.lab import nids_test_runner

    data = request.get_json() or {}
    stop_live = data.get("stop_live")
    if stop_live is not None:
        stop_live = bool(stop_live)
    return jsonify(nids_test_runner.stop_nids_soak(stop_lab=True, stop_live=stop_live))


@limiter.exempt
@api_bp.route("/nids-test/status")
def nids_test_status_route():
    from app.services.lab import nids_test_runner

    return jsonify(nids_test_runner.nids_soak_status())


@api_bp.route("/dashboard/overview")
def dashboard_overview():
    return jsonify(build_dashboard_context(dict(current_app.config)))
