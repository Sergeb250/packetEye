"""Scapy live capture fallback when Suricata is unavailable."""

import logging

logger = logging.getLogger(__name__)


class ScapyCapture:
    """Placeholder for optional scapy-based live capture.

    Suricata is the primary live ingest path. This module can be extended
    to sniff packets directly when Suricata is not installed.
    """

    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self._running = False

    def start(self):
        logger.warning(
            "Scapy live capture is not enabled. Use Suricata EVE JSON via LiveMonitor."
        )
        self._running = False

    def stop(self):
        self._running = False
