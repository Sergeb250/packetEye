"""Start live NIDS monitor without blocking the HTTP response."""

import logging
import threading

from flask import Flask, current_app

logger = logging.getLogger(__name__)


def kickoff_live_monitor(app: Flask, session_id: str) -> None:
    from app.tasks.live_tasks import start_live_monitor

    if app.config.get("CELERY_TASK_ALWAYS_EAGER"):
        def _run():
            with app.app_context():
                try:
                    start_live_monitor(session_id)
                except Exception:
                    logger.exception("Background live monitor failed for %s", session_id)

        thread = threading.Thread(
            target=_run,
            name=f"live-start-{session_id[:8]}",
            daemon=True,
        )
        thread.start()
        logger.info("Started background live monitor for %s", session_id)
    else:
        start_live_monitor.delay(session_id)


def kickoff_live_monitor_current(session_id: str) -> None:
    kickoff_live_monitor(current_app._get_current_object(), session_id)
