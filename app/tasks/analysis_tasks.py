"""Celery task chain for the analysis pipeline."""

import logging
from datetime import datetime, timezone

from app.extensions import celery_app, db
from app.models.analysis import Analysis, Flow, Finding, Observable
from app.services.detection.engine import DetectionEngine
from app.services.detection.scoring import compute_analysis_risk_score
from app.services.enrichment.orchestrator import EnrichmentOrchestrator
from app.services.llm.analyst import LLMAnalyst
from app.services.pcap_parser import PCAPParser
from app.services.report_builder import ReportBuilder

logger = logging.getLogger(__name__)


def _update_progress(analysis_id: str, status: str, pct: int):
    analysis = Analysis.query.get(analysis_id)
    if analysis:
        analysis.status = status
        analysis.progress_pct = pct
        db.session.commit()


@celery_app.task(name="parse_pcap")
def parse_pcap(analysis_id: str):
    from flask import current_app

    analysis = Analysis.query.get(analysis_id)
    if not analysis:
        return

    try:
        _update_progress(analysis_id, "parsing", 5)
        parser = PCAPParser(analysis.file_path)

        def progress_cb(pct):
            _update_progress(analysis_id, "parsing", pct)

        result = parser.parse(progress_callback=progress_cb)

        for flow_data in result["flows"]:
            flow = Flow(
                analysis_id=analysis_id,
                src_ip=flow_data["src_ip"],
                dst_ip=flow_data["dst_ip"],
                src_port=flow_data["src_port"],
                dst_port=flow_data["dst_port"],
                protocol=flow_data["protocol"],
                start_time=flow_data["start_time"],
                end_time=flow_data["end_time"],
                duration_ms=flow_data["duration_ms"],
                bytes_sent=flow_data["bytes_sent"],
                bytes_recv=flow_data["bytes_recv"],
                packets_sent=flow_data["packets_sent"],
                packets_recv=flow_data["packets_recv"],
                application_layer=flow_data.get("application_layer"),
                dns_queries=flow_data.get("dns_queries", []),
                http_hosts=flow_data.get("http_hosts", []),
                tls_sni=flow_data.get("tls_sni"),
                ja3_hash=flow_data.get("ja3_hash"),
                user_agents=flow_data.get("user_agents", []),
            )
            db.session.add(flow)

        for obs_data in result["observables"]:
            existing = Observable.query.filter_by(
                analysis_id=analysis_id, type=obs_data["type"], value=obs_data["value"]
            ).first()
            if existing:
                existing.occurrence_count = obs_data["occurrence_count"]
            else:
                obs = Observable(
                    analysis_id=analysis_id,
                    type=obs_data["type"],
                    value=obs_data["value"],
                    first_seen=obs_data.get("first_seen"),
                    occurrence_count=obs_data.get("occurrence_count", 1),
                )
                db.session.add(obs)

        analysis.total_flows = len(result["flows"])
        analysis.summary_json = {"arp_events": len(result.get("arp_events", []))}
        db.session.commit()

        analysis._arp_events = result.get("arp_events", [])
        _update_progress(analysis_id, "parsing", 25)

        enrich_observables.delay(analysis_id, result.get("arp_events", []))
    except Exception as exc:
        logger.exception("Parse failed for %s", analysis_id)
        analysis.status = "failed"
        analysis.error_message = str(exc)
        db.session.commit()
        raise


@celery_app.task(name="enrich_observables")
def enrich_observables(analysis_id: str, arp_events: list = None):
    from flask import current_app

    try:
        _update_progress(analysis_id, "enriching", 28)
        orchestrator = EnrichmentOrchestrator(dict(current_app.config))

        def progress_cb(pct):
            _update_progress(analysis_id, "enriching", pct)

        orchestrator.enrich_analysis_sync(analysis_id, progress_callback=progress_cb)
        _update_progress(analysis_id, "enriching", 55)
        run_detections.delay(analysis_id, arp_events or [])
    except Exception as exc:
        logger.exception("Enrichment failed for %s", analysis_id)
        analysis = Analysis.query.get(analysis_id)
        analysis.status = "failed"
        analysis.error_message = str(exc)
        db.session.commit()
        raise


@celery_app.task(name="run_detections")
def run_detections(analysis_id: str, arp_events: list = None):
    from flask import current_app

    try:
        _update_progress(analysis_id, "analyzing", 58)
        flows = Flow.query.filter_by(analysis_id=analysis_id).all()
        observables = Observable.query.filter_by(analysis_id=analysis_id).all()

        engine = DetectionEngine(dict(current_app.config))
        findings = engine.run(analysis_id, flows, arp_events or [], observables)

        for finding in findings:
            db.session.add(finding)

        db.session.commit()
        _update_progress(analysis_id, "analyzing", 70)
        run_llm_analysis.delay(analysis_id)
    except Exception as exc:
        logger.exception("Detection failed for %s", analysis_id)
        analysis = Analysis.query.get(analysis_id)
        analysis.status = "failed"
        analysis.error_message = str(exc)
        db.session.commit()
        raise


@celery_app.task(name="run_llm_analysis")
def run_llm_analysis(analysis_id: str):
    from flask import current_app

    try:
        _update_progress(analysis_id, "analyzing", 72)
        analyst = LLMAnalyst(dict(current_app.config))
        analyst.enrich_findings(analysis_id)
        _update_progress(analysis_id, "analyzing", 85)
        build_report.delay(analysis_id)
    except Exception as exc:
        logger.exception("LLM analysis failed for %s", analysis_id)
        build_report.delay(analysis_id)


@celery_app.task(name="build_report")
def build_report(analysis_id: str):
    from flask import current_app

    try:
        _update_progress(analysis_id, "analyzing", 92)
        analyst = LLMAnalyst(dict(current_app.config))
        executive_summary = analyst.generate_executive_summary(analysis_id)
        hunt_hypotheses = analyst.generate_hunt_hypotheses(analysis_id)

        builder = ReportBuilder()
        report = builder.build(analysis_id, executive_summary, hunt_hypotheses)

        analysis = Analysis.query.get(analysis_id)
        findings = Finding.query.filter_by(analysis_id=analysis_id, is_false_positive=False).all()

        analysis.report_json = report
        analysis.risk_score = report["risk_score"]
        analysis.total_findings = len(findings)
        analysis.summary_json = {
            **(analysis.summary_json or {}),
            **report["metrics"],
            "executive_summary": executive_summary,
            "hunt_hypotheses": hunt_hypotheses,
        }
        analysis.status = "complete"
        analysis.progress_pct = 100
        analysis.completed_at = datetime.now(timezone.utc)
        db.session.commit()
    except Exception as exc:
        logger.exception("Report build failed for %s", analysis_id)
        analysis = Analysis.query.get(analysis_id)
        analysis.status = "failed"
        analysis.error_message = str(exc)
        db.session.commit()
        raise


@celery_app.task(name="run_analysis")
def run_analysis(analysis_id: str):
    parse_pcap.delay(analysis_id)
