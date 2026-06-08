"""WHOIS and reverse DNS lookups."""

import asyncio
import logging
import socket
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


class WhoisClient:
    async def lookup_domain(self, domain: str) -> dict:
        return await asyncio.to_thread(self._lookup_domain_sync, domain)

    def _lookup_domain_sync(self, domain: str) -> dict:
        try:
            import whois

            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            newly_registered = False
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age = datetime.now(timezone.utc) - creation
                newly_registered = age < timedelta(days=30)

            return {
                "registrar": w.registrar,
                "creation_date": creation.isoformat() if creation else None,
                "expiry_date": (
                    w.expiration_date[0].isoformat()
                    if isinstance(w.expiration_date, list) and w.expiration_date
                    else (w.expiration_date.isoformat() if w.expiration_date else None)
                ),
                "name_servers": w.name_servers if w.name_servers else [],
                "org": w.org,
                "newly_registered": newly_registered,
            }
        except Exception as exc:
            logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
            return {}

    async def reverse_dns(self, ip: str) -> dict:
        return await asyncio.to_thread(self._reverse_dns_sync, ip)

    def _reverse_dns_sync(self, ip: str) -> dict:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return {"ptr": hostname}
        except (socket.herror, socket.gaierror):
            return {"ptr": None}
