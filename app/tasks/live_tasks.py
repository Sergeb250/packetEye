"""Celery tasks for live NIDS monitoring."""

import logging
import uuid
from datetime import datetime, timezone

from app.extensions import celery_app, db
from app.models.analysis import Analysis
from app.services.live.monitor import start_monitor, stop_monitor

logger = logging.getLogger(__name__)


@celery_app.task(name="start_live_monitor")
def start_live_monitor(session_id: str):
    from flask import current_app

    if not start_monitor(current_app._get_current_object(), session_id):
        logger.warning("Monitor already running for %s", session_id)


@celery_app.task(name="stop_live_monitor")
def stop_live_monitor_task(session_id: str):
    stop_monitor(session_id)


def create_live_session(config: dict, eve_path: str | None = None, interface: str | None = None) -> Analysis:
    session_id = str(uuid.uuid4())
    eve = eve_path or config.get("SURICATA_EVE_PATH", "")
    analysis = Analysis(
        id=session_id,
        filename=f"live-{interface or 'suricata'}",
        file_path=str(eve),
        analysis_name=f"Live NIDS {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}",
        source="live",
        status="analyzing",
        progress_pct=10,
        summary_json={"interface": interface, "eve_path": eve, "live": True},
    )
    db.session.add(analysis)
    db.session.commit()
    return analysis
