"""Async enrichment fan-out with Redis cache."""

import asyncio
import hashlib
import json
import logging
from typing import Any

from flask import current_app

from app.extensions import cache, db
from app.models.analysis import Observable
from app.services.enrichment.abuseipdb import AbuseIPDBClient
from app.services.enrichment.geo_asn import GeoASNClient
from app.services.enrichment.osint_public import (
    CrtShClient,
    GreyNoiseClient,
    OTXClient,
    ShodanInternetDBClient,
)
from app.services.enrichment.virustotal import VirusTotalClient
from app.services.enrichment.whois_lookup import WhoisClient

logger = logging.getLogger(__name__)


class EnrichmentOrchestrator:
    def __init__(self, app_config=None):
        self.config = app_config or {}
        self.vt = VirusTotalClient(self.config.get("VIRUSTOTAL_API_KEY", ""))
        self.abuse = AbuseIPDBClient(self.config.get("ABUSEIPDB_API_KEY", ""))
        self.geo = GeoASNClient(self.config.get("MAXMIND_DB_PATH", ""))
        self.whois = WhoisClient()
        # Keyless public OSINT (keys optional for higher rate limits)
        self.internetdb = ShodanInternetDBClient()
        self.otx = OTXClient(self.config.get("OTX_API_KEY", ""))
        self.greynoise = GreyNoiseClient(self.config.get("GREYNOISE_API_KEY", ""))
        self.crtsh = CrtShClient()
        self.cache_ttl = self.config.get("ENRICHMENT_CACHE_TTL_HOURS", 24) * 3600

    def _cache_key(self, provider: str, obs_type: str, value: str) -> str:
        return f"enrich:{provider}:{obs_type}:{hashlib.sha256(value.encode()).hexdigest()[:16]}"

    def _get_cached(self, provider: str, obs_type: str, value: str) -> dict | None:
        key = self._cache_key(provider, obs_type, value)
        try:
            result = cache.get(key)
            if result:
                return json.loads(result) if isinstance(result, str) else result
        except Exception:
            pass
        return None

    def _set_cache(self, provider: str, obs_type: str, value: str, data: dict):
        key = self._cache_key(provider, obs_type, value)
        try:
            cache.set(key, json.dumps(data), timeout=self.cache_ttl)
        except Exception as exc:
            logger.debug("Cache set failed: %s", exc)

    async def _enrich_ip(self, ip: str) -> dict:
        results = {}
        for provider, client, method in [
            ("virustotal", self.vt, "lookup_ip"),
            ("abuseipdb", self.abuse, "lookup_ip"),
            ("geo", self.geo, "lookup_ip"),
            ("whois", self.whois, "reverse_dns"),
            ("internetdb", self.internetdb, "lookup_ip"),
            ("otx", self.otx, "lookup_ip"),
            ("greynoise", self.greynoise, "lookup_ip"),
        ]:
            cached = self._get_cached(provider, "ip", ip)
            if cached:
                results[provider] = cached
                continue
            try:
                data = await getattr(client, method)(ip)
                if data:
                    results[provider] = data
                    self._set_cache(provider, "ip", ip, data)
            except Exception as exc:
                logger.warning("Enrichment %s for IP %s failed: %s", provider, ip, exc)
                results[provider] = {"error": str(exc)}
        return results

    async def _enrich_domain(self, domain: str) -> dict:
        results = {}
        for provider, client, method in [
            ("virustotal", self.vt, "lookup_domain"),
            ("whois", self.whois, "lookup_domain"),
            ("otx", self.otx, "lookup_domain"),
            ("crtsh", self.crtsh, "lookup_domain"),
        ]:
            cached = self._get_cached(provider, "domain", domain)
            if cached:
                results[provider] = cached
                continue
            try:
                data = await getattr(client, method)(domain)
                if data:
                    results[provider] = data
                    self._set_cache(provider, "domain", domain, data)
            except Exception as exc:
                logger.warning("Enrichment %s for domain %s failed: %s", provider, domain, exc)
        return results

    def _compute_verdict(self, enrichment: dict) -> tuple[bool, float]:
        malicious_signals = 0
        total_signals = 0
        confidence = 0.0

        vt = enrichment.get("virustotal", {})
        if vt and "malicious" in vt:
            total_signals += 1
            if vt.get("malicious", 0) > 2:
                malicious_signals += 1
                confidence += 0.4

        abuse = enrichment.get("abuseipdb", {})
        if abuse and "abuseConfidenceScore" in abuse:
            total_signals += 1
            if abuse.get("abuseConfidenceScore", 0) > 25:
                malicious_signals += 1
                confidence += 0.35

        whois = enrichment.get("whois", {})
        if whois and whois.get("newly_registered"):
            malicious_signals += 1
            confidence += 0.25

        otx = enrichment.get("otx", {})
        if otx and "pulse_count" in otx:
            total_signals += 1
            if otx.get("pulse_count", 0) > 2:
                malicious_signals += 1
                confidence += 0.25

        greynoise = enrichment.get("greynoise", {})
        if greynoise.get("classification") == "malicious":
            malicious_signals += 1
            confidence += 0.3
        elif greynoise.get("riot") or greynoise.get("classification") == "benign":
            # Known-good business service / research scanner — dampen.
            confidence = max(0.0, confidence - 0.2)

        if enrichment.get("internetdb", {}).get("vulns"):
            confidence += 0.1  # exposed vulnerable host — weak signal alone

        is_malicious = malicious_signals > 0
        confidence = min(1.0, confidence)
        return is_malicious, confidence

    async def enrich_observable(self, obs: Observable) -> dict:
        if obs.type == "ip":
            enrichment = await self._enrich_ip(obs.value)
        elif obs.type == "domain":
            enrichment = await self._enrich_domain(obs.value)
        else:
            enrichment = {}

        is_malicious, confidence = self._compute_verdict(enrichment)
        return {
            "enrichment_json": enrichment,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "status": "complete" if enrichment else "error",
        }

    async def enrich_all(self, analysis_id: str, progress_callback=None) -> int:
        observables = Observable.query.filter_by(analysis_id=analysis_id).all()
        total = len(observables)
        enriched = 0

        sem = asyncio.Semaphore(10)

        async def process_one(obs, idx):
            nonlocal enriched
            async with sem:
                result = await self.enrich_observable(obs)
                obs.enrichment_json = result["enrichment_json"]
                obs.is_malicious = result["is_malicious"]
                obs.confidence = result["confidence"]
                obs.enrichment_status = result["status"]
                enriched += 1
                if progress_callback:
                    pct = 25 + int((idx + 1) / max(total, 1) * 30)
                    progress_callback(min(55, pct))

        await asyncio.gather(*[process_one(obs, i) for i, obs in enumerate(observables)])
        db.session.commit()
        return enriched

    def enrich_analysis_sync(self, analysis_id: str, progress_callback=None) -> int:
        return asyncio.run(self.enrich_all(analysis_id, progress_callback))


def get_orchestrator():
    return EnrichmentOrchestrator(dict(current_app.config))
