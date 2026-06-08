import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask

from app.config import config_by_name
from app.extensions import cache, celery_app, db, init_celery, limiter, login_manager


def create_app(config_name=None):
    load_dotenv()

    app = Flask(__name__)
    config_name = config_name or os.environ.get("FLASK_ENV", "development")
    app.config.from_object(config_by_name.get(config_name, config_by_name["default"]))

    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    Path(app.config.get("ML_MODEL_PATH", "")).parent.mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    cache.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    limiter.init_app(app)

    init_celery(app, celery_app)

    from app.routes.main import main_bp
    from app.routes.api import api_bp
    from app.routes.auth import auth_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(auth_bp, url_prefix="/auth")

    @app.context_processor
    def inject_config():
        return {"config": app.config}

    with app.app_context():
        db.create_all()

    # Register Celery tasks
    import app.tasks.analysis_tasks  # noqa: F401

    return app
