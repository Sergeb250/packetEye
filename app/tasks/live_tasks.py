"""Celery tasks for live NIDS monitoring."""

import logging

from app.extensions import celery_app
from app.services.live.monitor import start_monitor, stop_monitor
from app.services.streams import get_session_store

logger = logging.getLogger(__name__)


@celery_app.task(name="start_live_monitor")
def start_live_monitor(session_id: str):
    from flask import current_app

    if not start_monitor(current_app._get_current_object(), session_id):
        logger.warning("Monitor already running for %s", session_id)


@celery_app.task(name="stop_live_monitor")
def stop_live_monitor_task(session_id: str):
    stop_monitor(session_id)


def create_live_session(
    config: dict,
    eve_path: str | None = None,
    interface: str | None = None,
    capture_source: str = "suricata",
) -> dict:
    store = get_session_store()
    if not store:
        raise RuntimeError("Live session store not initialized")
    return store.create(
        eve_path=eve_path or config.get("SURICATA_EVE_PATH", ""),
        interface=interface,
        capture_source=capture_source,
    )
