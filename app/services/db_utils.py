"""DB session hygiene for long-lived background threads.

The live monitor, LLM packet triage, and enrichment threads keep one app
context (and therefore one scoped session) alive for their whole lifetime.
A failed flush/commit leaves that session in PendingRollbackError until
someone rolls it back — every later batch then fails with the same error
until the process restarts. These helpers reset the session after a failure
and release it between iterations so pooled connections are not held across
poll sleeps.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager

from app.extensions import db

logger = logging.getLogger(__name__)


def reset_db_session() -> None:
    """Roll back any poisoned transaction and dispose the scoped session."""
    try:
        db.session.rollback()
    except Exception:
        logger.debug("DB session rollback failed", exc_info=True)
    try:
        db.session.remove()
    except Exception:
        logger.debug("DB session remove failed", exc_info=True)


def release_db_session() -> None:
    """Return the session (and its pooled connection) after a clean iteration."""
    try:
        db.session.remove()
    except Exception:
        logger.debug("DB session release failed", exc_info=True)


@contextmanager
def db_session_guard(context: str = "background task"):
    """Wrap one loop iteration: log + reset the session on failure, release on success."""
    try:
        yield
    except Exception:
        logger.exception("%s failed — resetting DB session", context)
        reset_db_session()
    else:
        release_db_session()
