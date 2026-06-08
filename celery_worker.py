"""Celery worker entry point."""

import os

from app import create_app
from app.extensions import celery_app

flask_app = create_app(os.environ.get("FLASK_ENV", "development"))

# Import tasks so Celery registers them
import app.tasks.analysis_tasks  # noqa: E402, F401

if __name__ == "__main__":
    celery_app.start()
