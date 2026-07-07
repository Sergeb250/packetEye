import pytest

from app import create_app
from app.extensions import db


@pytest.fixture
def flask_app(tmp_path):
    stream_dir = tmp_path / "streams"
    application = create_app("testing")
    application.config["STREAM_DATA_DIR"] = str(stream_dir)
    from app.services.streams import init_streams

    init_streams(dict(application.config))
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def app(flask_app):
    """Alias for compatibility with Flask test patterns."""
    return flask_app
