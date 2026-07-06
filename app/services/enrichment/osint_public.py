"""Free public OSINT sources — no API key required (keys optional for higher limits).

- Shodan InternetDB: open ports, known vulns, tags for an IP (keyless)
- AlienVault OTX: community threat-pulse counts for IPs/domains (keyless)
- GreyNoise Community: scanner/benign-service classification (key optional)
- crt.sh: certificate-transparency history for domains (keyless)
"""

from __future__ import annotations

import logging

import aiohttp

logger = logging.getLogger(__name__)

_TIMEOUT = aiohttp.ClientTimeout(total=12)


class ShodanInternetDBClient:
    """https://internetdb.shodan.io — fast, keyless port/vuln snapshot."""

    async def lookup_ip(self, ip: str) -> dict:
        url = f"https://internetdb.shodan.io/{ip}"
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(url) as resp:
                if resp.status == 404:
                    return {"ports": [], "vulns": [], "tags": [], "note": "no data"}
                if resp.status != 200:
                    logger.debug("InternetDB lookup failed: %s", resp.status)
                    return {}
                data = await resp.json()
                return {
                    "ports": data.get("ports", [])[:20],
                    "vulns": data.get("vulns", [])[:15],
                    "tags": data.get("tags", []),
                    "hostnames": data.get("hostnames", [])[:5],
                }


class OTXClient:
    """AlienVault OTX — pulse (community threat report) counts."""

    BASE = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key} if self.api_key else {}

    async def _general(self, path: str) -> dict:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(f"{self.BASE}/{path}/general", headers=self._headers()) as resp:
                if resp.status != 200:
                    logger.debug("OTX lookup failed: %s", resp.status)
                    return {}
                data = await resp.json()
                pulses = data.get("pulse_info", {}) or {}
                names = [p.get("name", "") for p in (pulses.get("pulses") or [])[:5]]
                return {
                    "pulse_count": pulses.get("count", 0),
                    "pulses": [n for n in names if n],
                    "reputation": data.get("reputation", 0),
                }

    async def lookup_ip(self, ip: str) -> dict:
        return await self._general(f"IPv4/{ip}")

    async def lookup_domain(self, domain: str) -> dict:
        return await self._general(f"domain/{domain}")


class GreyNoiseClient:
    """GreyNoise Community — is this IP internet-wide scan noise or targeted?"""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> dict:
        headers = {"key": self.api_key} if self.api_key else {}
        url = f"https://api.greynoise.io/v3/community/{ip}"
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 404:
                    return {"classification": "unknown", "note": "not seen scanning"}
                if resp.status != 200:
                    logger.debug("GreyNoise lookup failed: %s", resp.status)
                    return {}
                data = await resp.json()
                return {
                    "classification": data.get("classification"),
                    "name": data.get("name"),
                    "riot": data.get("riot"),  # true = known-good business service
                    "last_seen": data.get("last_seen"),
                }


class CrtShClient:
    """crt.sh certificate transparency — infra footprint of a domain."""

    async def lookup_domain(self, domain: str) -> dict:
        url = f"https://crt.sh/?q={domain}&output=json"
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return {}
                    data = await resp.json(content_type=None)
        except Exception as exc:  # crt.sh is frequently slow/unavailable
            logger.debug("crt.sh lookup failed: %s", exc)
            return {}
        if not isinstance(data, list):
            return {}
        names = sorted({row.get("common_name", "") for row in data if row.get("common_name")})
        return {
            "cert_count": len(data),
            "recent_names": [n for n in names if n][:8],
        }


class ShodanApiClient:
    """Shodan REST API (requires SHODAN_API_KEY)."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> dict:
        if not self.api_key:
            return {}
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                return {
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "ports": (data.get("ports") or [])[:15],
                    "tags": data.get("tags", [])[:10],
                    "vulns": list((data.get("vulns") or {}).keys())[:10],
                }


class URLScanClient:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    async def lookup_domain(self, domain: str) -> dict:
        if not self.api_key:
            return {}
        headers = {"API-Key": self.api_key}
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                results = data.get("results") or []
                return {"scan_count": len(results), "recent": [r.get("page", {}).get("url") for r in results[:5]]}


class PulsediveClient:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> dict:
        if not self.api_key:
            return {}
        url = "https://pulsedive.com/api/info.php"
        params = {"indicator": ip, "key": self.api_key}
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                return {
                    "risk": data.get("risk"),
                    "risk_recommended": data.get("risk_recommended"),
                    "attributes": (data.get("attributes") or [])[:8],
                }


class IPInfoClient:
    def __init__(self, token: str = ""):
        self.token = token

    async def lookup_ip(self, ip: str) -> dict:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                return {
                    "org": data.get("org"),
                    "hostname": data.get("hostname"),
                    "city": data.get("city"),
                    "country": data.get("country"),
                }


class ThreatFoxClient:
    """abuse.ch ThreatFox — public IOC lookup."""

    async def lookup_ip(self, ip: str) -> dict:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": ip}
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                iocs = data.get("data") or []
                return {"ioc_count": len(iocs), "malware": list({i.get("malware") for i in iocs if i.get("malware")})[:5]}
