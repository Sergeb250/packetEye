"""Kick off PCAP analysis without blocking the upload HTTP response."""

import logging
import threading

from flask import Flask, current_app

logger = logging.getLogger(__name__)


def kickoff_analysis(app: Flask, analysis_id: str) -> None:
    """Queue analysis on Celery, or run in a background thread when eager/dev."""
    from app.tasks.analysis_tasks import run_analysis

    if app.config.get("CELERY_TASK_ALWAYS_EAGER"):
        def _run():
            with app.app_context():
                try:
                    run_analysis(analysis_id)
                except Exception:
                    logger.exception("Background analysis failed for %s", analysis_id)

        thread = threading.Thread(target=_run, name=f"analysis-{analysis_id[:8]}", daemon=True)
        thread.start()
        logger.info("Started background analysis thread for %s", analysis_id)
    else:
        run_analysis.delay(analysis_id)
        logger.info("Queued Celery analysis for %s", analysis_id)


def kickoff_analysis_current(analysis_id: str) -> None:
    kickoff_analysis(current_app._get_current_object(), analysis_id)
