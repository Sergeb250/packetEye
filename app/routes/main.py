import os
import uuid
from pathlib import Path

from flask import Blueprint, current_app, render_template, request

from app.extensions import db, limiter
from app.models.analysis import Analysis
from app.services.pcap_parser import validate_pcap_magic

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/dashboard")
def dashboard():
    analyses = Analysis.query.order_by(Analysis.created_at.desc()).limit(50).all()
    return render_template("dashboard.html", analyses=analyses)


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
