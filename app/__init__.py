import logging
import os
from pathlib import Path

from dotenv import load_dotenv

# .env must be loaded BEFORE app.config is imported — Config class attributes
# read os.environ at import time, so a late load_dotenv() is silently ignored
# (and the Werkzeug reloader child then sees different config than the parent).
load_dotenv()

from flask import Flask

from app.config import config_by_name
from app.extensions import cache, celery_app, db, init_celery, limiter, login_manager

logger = logging.getLogger(__name__)


def _ensure_dir(directory) -> None:
    """Best-effort create; a bad configured path must not kill startup."""
    if not directory:
        return
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create directory %s (%s) — check your .env paths", directory, exc)


def create_app(config_name=None):
    flask_app = Flask(__name__)
    config_name = config_name or os.environ.get("FLASK_ENV", "development")
    flask_app.config.from_object(config_by_name.get(config_name, config_by_name["default"]))

    from app.services.capture.privileges import resolve_tcpdump_chunk_dir

    if not str(flask_app.config.get("TCPDUMP_CHUNK_DIR") or "").strip():
        flask_app.config["TCPDUMP_CHUNK_DIR"] = str(
            resolve_tcpdump_chunk_dir(dict(flask_app.config))
        )

    _ensure_dir(flask_app.config["UPLOAD_FOLDER"])
    ml_path = flask_app.config.get("ML_MODEL_PATH", "")
    if ml_path:
        _ensure_dir(Path(ml_path).parent)
    _ensure_dir(flask_app.config.get("CAPTURE_STATE_DIR"))
    _ensure_dir(flask_app.config.get("TCPDUMP_CHUNK_DIR"))
    _ensure_dir(flask_app.config.get("SURICATA_LOG_DIR"))
    # EVE log: Suricata writes it, packetEye only reads it — creating its
    # parent is a convenience for the in-project default, never a requirement.
    eve = flask_app.config.get("SURICATA_EVE_PATH", "")
    if eve and not Path(eve).parent.exists():
        _ensure_dir(Path(eve).parent)

    db.init_app(flask_app)
    cache.init_app(flask_app)
    login_manager.init_app(flask_app)
    login_manager.login_view = "auth.login"
    limiter.init_app(flask_app)

    init_celery(flask_app, celery_app)

    from app.routes.main import main_bp
    from app.routes.api import api_bp
    from app.routes.auth import auth_bp

    flask_app.register_blueprint(main_bp)
    flask_app.register_blueprint(api_bp, url_prefix="/api")
    flask_app.register_blueprint(auth_bp, url_prefix="/auth")

    @flask_app.context_processor
    def inject_config():
        from app.routes.main import LIVE_ENDPOINTS
        return {"config": flask_app.config, "live_endpoints": LIVE_ENDPOINTS}

    with flask_app.app_context():
        db.create_all()

    if flask_app.config.get("LIVE_MONITOR_ENABLED"):
        try:
            from app.services.capture.privileges import ensure_capture_paths

            path_errors = ensure_capture_paths(dict(flask_app.config))
            for name, err in path_errors.items():
                if err:
                    logger.warning("Capture path %s: %s", name, err)
        except Exception as exc:
            logger.warning("Capture path setup failed: %s", exc)

    # Register Celery tasks (import module, not `app` — avoids shadowing flask_app)
    from app.tasks import analysis_tasks  # noqa: F401
    from app.tasks import live_tasks  # noqa: F401

    return flask_app
