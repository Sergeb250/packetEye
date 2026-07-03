import pytest

from app import create_app
from app.extensions import db


@pytest.fixture
def flask_app():
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def app(flask_app):
    """Alias for compatibility with Flask test patterns."""
    return flask_app
