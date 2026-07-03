"""VirusTotal API client."""

import asyncio
import logging
import time

import aiohttp

logger = logging.getLogger(__name__)


class TokenBucket:
    def __init__(self, rate_per_minute: float = 4):
        self.rate = rate_per_minute / 60.0
        self.tokens = rate_per_minute
        self.max_tokens = rate_per_minute
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
            self.last = now
            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1


_vt_bucket = TokenBucket(4)


class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> dict:
        if not self.api_key:
            return {}
        await _vt_bucket.acquire()
        url = f"{self.BASE}/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=30) as resp:
                if resp.status == 404:
                    return {"malicious": 0, "suspicious": 0, "undetected": 0}
                if resp.status != 200:
                    logger.warning("VT IP lookup failed: %s", resp.status)
                    return {}
                data = await resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                    "tags": data.get("data", {}).get("attributes", {}).get("tags", []),
                }

    async def lookup_domain(self, domain: str) -> dict:
        if not self.api_key:
            return {}
        await _vt_bucket.acquire()
        url = f"{self.BASE}/domains/{domain}"
        headers = {"x-apikey": self.api_key}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=30) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                }

    async def lookup_hash(self, file_hash: str) -> dict:
        if not self.api_key:
            return {}
        await _vt_bucket.acquire()
        url = f"{self.BASE}/files/{file_hash}"
        headers = {"x-apikey": self.api_key}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=30) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {"malicious": stats.get("malicious", 0), "sha256": file_hash}
