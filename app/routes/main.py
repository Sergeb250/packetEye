import os
import uuid
from pathlib import Path

from flask import Blueprint, current_app, redirect, render_template, request, url_for

from app.extensions import db, limiter
from app.models.analysis import Analysis, Finding
from app.services.ml_dashboard import (
    build_dashboard_context,
    build_live_monitor_context,
    build_ml_performance,
)
from app.services.pcap_parser import validate_pcap_magic

main_bp = Blueprint("main", __name__)

LIVE_ENDPOINTS = (
    "main.live_overview",
    "main.live_capture",
    "main.live_suricata",
    "main.live_ml",
    "main.live_lab",
    "main.live_alerts",
)


def _live_context():
    return build_live_monitor_context(dict(current_app.config))


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/live")
@main_bp.route("/live/overview")
def live_overview():
    return render_template("live/ops_center.html", live=_live_context(), live_page="overview")


@main_bp.route("/live/capture")
def live_capture():
    return render_template("live/ops_center.html", live=_live_context(), live_page="capture")


@main_bp.route("/live/suricata")
def live_suricata():
    return render_template("live/ops_center.html", live=_live_context(), live_page="suricata")


@main_bp.route("/live/ml")
def live_ml():
    return render_template("live/ops_center.html", live=_live_context(), live_page="ml")


@main_bp.route("/live/lab")
def live_lab():
    return render_template("live/ops_center.html", live=_live_context(), live_page="lab")


@main_bp.route("/live/alerts")
def live_alerts():
    return redirect(url_for("main.live_ml"))


@main_bp.route("/dashboard")
def dashboard():
    recent = Analysis.query.order_by(Analysis.created_at.desc()).limit(6).all()
    latest_findings = (
        Finding.query.filter_by(is_false_positive=False)
        .order_by(Finding.created_at.desc())
        .limit(8)
        .all()
    )
    ctx = build_dashboard_context(dict(current_app.config))
    return render_template(
        "dashboard.html",
        recent=recent,
        latest_findings=latest_findings,
        overview=ctx["analysis_overview"],
        ml=ctx["ml_performance"],
        live=ctx["live_monitor"],
    )


@main_bp.route("/ml")
def ml_performance():
    ml = build_ml_performance(dict(current_app.config))
    return render_template("ml_performance.html", ml=ml)


@main_bp.route("/analyses")
def analyses():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    source = (request.args.get("source") or "").strip()
    page = max(1, request.args.get("page", 1, type=int))

    query = Analysis.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(Analysis.filename.ilike(like), Analysis.analysis_name.ilike(like))
        )
    if status:
        query = query.filter(Analysis.status == status)
    if source == "live":
        query = query.filter(Analysis.source == "live")
    elif source == "pcap":
        query = query.filter(db.or_(Analysis.source != "live", Analysis.source.is_(None)))

    pagination = query.order_by(Analysis.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )
    return render_template(
        "analyses.html",
        pagination=pagination,
        analyses=pagination.items,
        q=q,
        status=status,
        source=source,
    )


@main_bp.route("/analysis/<analysis_id>")
def analysis_progress(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    return render_template("analysis_progress.html", analysis=analysis)


@main_bp.route("/report/<analysis_id>")
def report(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    report_data = analysis.report_json or {}
    findings = analysis.findings.filter_by(is_false_positive=False).all()
    flows = analysis.flows.limit(100).all()
    observables = analysis.observables.all()
    return render_template(
        "report.html",
        analysis=analysis,
        report=report_data,
        findings=findings,
        flows=flows,
        observables=observables,
    )
