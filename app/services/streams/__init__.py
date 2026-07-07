"""JSON streaming layer for live monitor data."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.streams.alert_writer import AlertStreamWriter
from app.services.streams.incident_tracker import IncidentTracker
from app.services.streams.packet_writer import PacketStreamWriter
from app.services.streams.session_store import LiveSessionStore

_session_store: LiveSessionStore | None = None
_alert_writer: AlertStreamWriter | None = None
_packet_writer: PacketStreamWriter | None = None
_incident_tracker: IncidentTracker | None = None


def init_streams(config: dict[str, Any]) -> None:
    global _session_store, _alert_writer, _packet_writer, _incident_tracker
    base = Path(config.get("STREAM_DATA_DIR") or (config.get("BASE_DIR") / "data" / "streams"))
    base.mkdir(parents=True, exist_ok=True)
    for sub in ("packets", "alerts", "sessions", "incidents"):
        (base / sub).mkdir(parents=True, exist_ok=True)

    _session_store = LiveSessionStore(base / "sessions")
    _alert_writer = AlertStreamWriter(
        base / "alerts",
        enabled=bool(config.get("ALERT_STREAM_ENABLED", True)),
    )
    _packet_writer = PacketStreamWriter(
        base / "packets",
        enabled=bool(config.get("PACKET_STREAM_ENABLED", True)),
    )
    _incident_tracker = IncidentTracker(base / "incidents")


def get_session_store() -> LiveSessionStore | None:
    return _session_store


def get_alert_writer() -> AlertStreamWriter | None:
    return _alert_writer


def get_packet_writer() -> PacketStreamWriter | None:
    return _packet_writer


def get_incident_tracker() -> IncidentTracker | None:
    return _incident_tracker
