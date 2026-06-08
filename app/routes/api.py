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
from app.tasks.analysis_tasks import run_analysis

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
    )
    db.session.add(analysis)
    db.session.commit()

    run_analysis.delay(analysis_id)

    return jsonify({"analysis_id": analysis_id, "status": "queued"}), 201


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
            "virustotal_configured": bool(config.get("VIRUSTOTAL_API_KEY")),
            "abuseipdb_configured": bool(config.get("ABUSEIPDB_API_KEY")),
        }
    )
