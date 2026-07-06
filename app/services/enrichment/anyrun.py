"""ANY.RUN Threat Intelligence Lookup client."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

import aiohttp

logger = logging.getLogger(__name__)

VERDICT_MAP = {0: "No info", 1: "Suspicious", 2: "Malicious"}


class AnyRunClient:
    BASE = "https://api.any.run/v1"
    LOOKUP_DEPTH_DAYS = 180

    def __init__(self, api_key: str, lookup_depth: int = LOOKUP_DEPTH_DAYS):
        self.api_key = api_key
        self.lookup_depth = lookup_depth

    def _headers(self) -> dict:
        return {"Authorization": self.api_key, "Content-Type": "application/json"}

    def _date_range(self) -> tuple[str, str]:
        end = datetime.utcnow().date()
        start = end - timedelta(days=self.lookup_depth)
        return start.isoformat(), end.isoformat()

    async def _search(self, query: str) -> dict:
        if not self.api_key:
            return {}
        start_date, end_date = self._date_range()
        body = {"query": query, "startDate": start_date, "endDate": end_date}
        url = f"{self.BASE}/intelligence/api/search"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=body, headers=self._headers(), timeout=45
                ) as resp:
                    if resp.status == 401:
                        logger.warning("AnyRun auth failed — check ANYRUN_API_KEY")
                        return {"error": "unauthorized"}
                    if resp.status != 200:
                        logger.debug("AnyRun lookup failed: HTTP %s", resp.status)
                        return {}
                    data = await resp.json()
                    return self._normalize(data)
        except Exception as exc:
            logger.warning("AnyRun lookup error: %s", exc)
            return {"error": str(exc)}

    @staticmethod
    def _normalize(raw: dict) -> dict:
        if not raw:
            return {}
        summary = raw.get("summary") or {}
        threat_level = summary.get("threatLevel")
        tags = summary.get("tags") or []
        tasks = raw.get("sourceTasks") or []
        related_ips = raw.get("destinationIP") or []
        related_dns = raw.get("relatedDNS") or []
        related_urls = raw.get("relatedURLs") or []
        return {
            "threat_level": threat_level,
            "verdict": VERDICT_MAP.get(threat_level, "No info") if threat_level is not None else "No info",
            "tags": tags[:10],
            "task_count": len(tasks),
            "related_ip_count": len(related_ips),
            "related_dns_count": len(related_dns),
            "related_url_count": len(related_urls),
            "last_seen": summary.get("lastSeen"),
            "lookup_url": "https://intelligence.any.run/analysis/lookup",
            "raw_summary": summary,
        }

    async def lookup_ip(self, ip: str) -> dict:
        return await self._search(f'destinationIP:"{ip}"')

    async def lookup_domain(self, domain: str) -> dict:
        return await self._search(f'domainName:"{domain}"')

    async def lookup_hash(self, value: str) -> dict:
        value = value.strip().lower()
        if len(value) == 64:
            field = "sha256"
        elif len(value) == 40:
            field = "sha1"
        elif len(value) == 32:
            field = "md5"
        else:
            return {}
        return await self._search(f'{field}:"{value}"')
