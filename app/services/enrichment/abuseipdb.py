"""AbuseIPDB API client."""

import aiohttp
import logging

logger = logging.getLogger(__name__)


class AbuseIPDBClient:
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> dict:
        if not self.api_key:
            return {}
        url = f"{self.BASE}/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=30) as resp:
                if resp.status != 200:
                    logger.warning("AbuseIPDB lookup failed: %s", resp.status)
                    return {}
                data = await resp.json()
                attrs = data.get("data", {})
                return {
                    "abuseConfidenceScore": attrs.get("abuseConfidenceScore", 0),
                    "totalReports": attrs.get("totalReports", 0),
                    "lastReportedAt": attrs.get("lastReportedAt"),
                    "usageType": attrs.get("usageType"),
                    "isp": attrs.get("isp"),
                    "countryCode": attrs.get("countryCode"),
                }
