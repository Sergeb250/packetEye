"""Aggregate ML model performance and analysis overview for the dashboard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import func

from app.extensions import db
from app.models.analysis import Analysis, Finding


def _load_json(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _verification_from_tracker(run: dict | None) -> dict | None:
    if not run:
        return None
    for phase in run.get("phases") or []:
        if phase.get("name") == "verification" and phase.get("metrics"):
            metrics = dict(phase["metrics"])
            metrics["status"] = phase.get("status")
            metrics["detail"] = phase.get("detail")
            return metrics
    verify = (run.get("verify_meta") or {}).get("verify_metrics")
    return dict(verify) if verify else None


def _list_training_runs(tracker_dir: Path) -> list[dict]:
    if not tracker_dir.is_dir():
        return []
    runs = []
    for path in sorted(tracker_dir.glob("run_*.json"), reverse=True):
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        verify = _verification_from_tracker(data)
        runs.append(
            {
                "run_id": data.get("run_id"),
                "path": str(path.name),
                "dataset_preset": (data.get("config") or {}).get("dataset_label"),
                "train_rows": ((data.get("phases") or [{}])[0].get("metrics") or {}).get("train_rows"),
                "verification": verify,
            }
        )
    return runs[:10]


def build_analysis_overview() -> dict[str, Any]:
    total = Analysis.query.count()
    complete = Analysis.query.filter_by(status="complete").count()
    failed = Analysis.query.filter_by(status="failed").count()
    in_progress = total - complete - failed

    pcap_count = Analysis.query.filter(Analysis.source != "live").count()
    live_count = Analysis.query.filter_by(source="live").count()

    avg_risk = db.session.query(func.avg(Analysis.risk_score)).filter(
        Analysis.status == "complete"
    ).scalar()

    total_flows = db.session.query(func.sum(Analysis.total_flows)).scalar() or 0
    total_findings = db.session.query(func.sum(Analysis.total_findings)).scalar() or 0

    ml_findings = Finding.query.filter_by(source="ml", is_false_positive=False).count()
    rule_findings = Finding.query.filter_by(source="rule", is_false_positive=False).count()

    by_source = (
        db.session.query(Finding.source, func.count(Finding.id))
        .filter(Finding.is_false_positive == False)  # noqa: E712
        .group_by(Finding.source)
        .all()
    )

    return {
        "total_analyses": total,
        "complete": complete,
        "failed": failed,
        "in_progress": in_progress,
        "pcap_count": pcap_count,
        "live_count": live_count,
        "avg_risk_score": round(float(avg_risk or 0), 2),
        "total_flows": int(total_flows),
        "total_findings": int(total_findings),
        "ml_findings": ml_findings,
        "rule_findings": rule_findings,
        "findings_by_source": {src or "unknown": cnt for src, cnt in by_source},
    }


def build_ml_performance(config: dict) -> dict[str, Any]:
    ml_dir = Path(config.get("ML_MODEL_PATH", "")).parent
    model_path = Path(config.get("ML_MODEL_PATH", ""))
    scaler_path = Path(config.get("ML_SCALER_PATH", ""))
    schema_path = Path(config.get("ML_FEATURE_SCHEMA_PATH", ""))

    training_meta = _load_json(ml_dir / "training_metadata.json")
    if not isinstance(training_meta, dict):
        training_meta = {}

    benchmark = _load_json(ml_dir / "benchmark_results.json")
    if not isinstance(benchmark, dict):
        benchmark = {}

    threshold_data = _load_json(ml_dir / "recommended_threshold.json")
    if not isinstance(threshold_data, dict):
        threshold_data = {}

    latest_run = _load_json(ml_dir / "training_tracker" / "latest_run.json")
    if not isinstance(latest_run, dict):
        latest_run = None

    verification = _verification_from_tracker(latest_run)
    if not verification and benchmark.get("overall"):
        overall = benchmark["overall"]
        verification = {
            "split": overall.get("split", "benchmark"),
            "samples": overall.get("samples"),
            "attacks": overall.get("attacks"),
            "benign": overall.get("benign"),
            "predicted_anomalies": overall.get("predicted_anomalies"),
            "accuracy": overall.get("accuracy"),
            "precision": overall.get("precision"),
            "recall": overall.get("recall"),
            "f1": overall.get("f1"),
            "source": "benchmark_results.json",
        }

    recommended = threshold_data.get("recommended") if threshold_data else None
    sweep = threshold_data.get("sweep") if threshold_data else []

    attack_breakdown = []
    by_label = benchmark.get("by_attack_label") or {}
    for label, metrics in sorted(by_label.items(), key=lambda x: x[1].get("recall", 0), reverse=True):
        attack_breakdown.append(
            {
                "label": label,
                "samples": metrics.get("samples"),
                "recall": metrics.get("recall"),
                "precision": metrics.get("precision"),
                "f1": metrics.get("f1"),
            }
        )

    return {
        "model_loaded": model_path.is_file() and scaler_path.is_file(),
        "artifacts": {
            "model": model_path.is_file(),
            "scaler": scaler_path.is_file(),
            "schema": schema_path.is_file(),
            "benchmark": (ml_dir / "benchmark_results.json").is_file(),
        },
        "training": training_meta,
        "verification": verification,
        "benchmark_summary": benchmark.get("summary") or benchmark.get("overall"),
        "attack_breakdown": attack_breakdown[:12],
        "threshold": {
            "current": float(config.get("ML_ANOMALY_THRESHOLD", 5.0)),
            "recommended": recommended,
            "sweep": sweep,
        },
        "training_runs": _list_training_runs(ml_dir / "training_tracker"),
        "latest_run_id": (latest_run or {}).get("run_id"),
    }


def build_live_monitor_context(config: dict) -> dict[str, Any]:
    """Live ML traffic monitor status for dashboard and /live page."""
    import os

    from app.services.live.monitor import monitor_status

    model_path = Path(config.get("ML_MODEL_PATH", ""))
    scaler_path = Path(config.get("ML_SCALER_PATH", ""))
    eve_default = str(config.get("SURICATA_EVE_PATH") or "")
    eve_path = Path(eve_default) if eve_default else None

    latest_live = (
        Analysis.query.filter_by(source="live")
        .order_by(Analysis.created_at.desc())
        .first()
    )
    active = None
    if latest_live:
        status = monitor_status(latest_live.id)
        if status.get("running"):
            active = status

    calibration_path = Path(str(config.get("ML_SCORE_CALIBRATION_PATH", "")))
    suricata = {"installed": False, "running": False, "version": None}
    capture = {"running": False, "mode": None, "interface": None, "eve_path": eve_default}
    try:
        from app.services.capture.orchestrator import capture_status
        from app.services.live.suricata_manager import get_status

        status = get_status(config)
        suricata = {
            "installed": status.get("installed", False),
            "running": status.get("running", False),
            "managed": status.get("managed", False),
            "version": status.get("version"),
            "config_path": status.get("config_path"),
            "config_source": status.get("config_source"),
        }
        cap = capture_status(config)
        eve_from_capture = (cap.get("suricata") or {}).get("eve", {}).get("path")
        capture = {
            "running": bool(cap.get("running")),
            "mode": cap.get("mode"),
            "interface": cap.get("interface"),
            "eve_path": eve_from_capture or eve_default,
        }
        if eve_from_capture:
            eve_default = eve_from_capture
    except Exception:  # dashboard must render even if process probing fails
        pass

    privilege_hint = None
    if os.name != "nt":
        try:
            from app.services.capture.privileges import live_capture_privilege_hint, running_as_root

            privilege_hint = live_capture_privilege_hint()
            running_root = running_as_root()
        except Exception:
            running_root = False
    else:
        running_root = False

    eve_exists = bool(eve_path and eve_path.is_file())
    return {
        "enabled": bool(config.get("LIVE_MONITOR_ENABLED")),
        "default_eve_path": eve_default,
        "eve_exists": eve_exists,
        "eve_size_bytes": eve_path.stat().st_size if eve_exists else 0,
        "ml_loaded": model_path.is_file() and scaler_path.is_file(),
        "score_calibrated": calibration_path.is_file(),
        "threshold": float(config.get("ML_ANOMALY_THRESHOLD", 5.0)),
        "suricata": suricata,
        "capture": capture,
        "running_as_root": running_root,
        "privilege_hint": privilege_hint,
        "capture_mode": str(config.get("CAPTURE_MODE") or "suricata"),
        "capture_interface": str(config.get("CAPTURE_INTERFACE") or ""),
        "suricata_allow_loopback": bool(config.get("SURICATA_ALLOW_LOOPBACK")),
        "enrichment_mode": str(config.get("ENRICHMENT_MODE") or "on_investigate"),
        "webhook_enabled": bool(config.get("ALERT_WEBHOOK_URL")),
        "chatbot_enabled": bool(config.get("CHATBOT_ENABLED", True)),
        "active_session": active,
        "latest_session_id": latest_live.id if latest_live else None,
    }


def build_dashboard_context(config: dict) -> dict[str, Any]:
    return {
        "analysis_overview": build_analysis_overview(),
        "ml_performance": build_ml_performance(config),
        "live_monitor": build_live_monitor_context(config),
    }
