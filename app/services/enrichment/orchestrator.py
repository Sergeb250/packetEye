"""Async enrichment fan-out with Redis cache."""

import asyncio
import hashlib
import json
import logging
from typing import Any

from flask import current_app

from app.extensions import cache, db
from app.models.analysis import Observable
from app.services.enrichment.anyrun import AnyRunClient
from app.services.enrichment.abuseipdb import AbuseIPDBClient
from app.services.enrichment.geo_asn import GeoASNClient
from app.services.enrichment.osint_public import (
    CrtShClient,
    GreyNoiseClient,
    IPInfoClient,
    OTXClient,
    PulsediveClient,
    ShodanApiClient,
    ShodanInternetDBClient,
    ThreatFoxClient,
    URLScanClient,
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
        self.shodan_api = ShodanApiClient(self.config.get("SHODAN_API_KEY", ""))
        self.urlscan = URLScanClient(self.config.get("URLSCAN_API_KEY", ""))
        self.pulsedive = PulsediveClient(self.config.get("PULSEDIVE_API_KEY", ""))
        self.ipinfo = IPInfoClient(self.config.get("IPINFO_TOKEN", ""))
        self.threatfox = ThreatFoxClient()
        self.anyrun = AnyRunClient(
            self.config.get("ANYRUN_API_KEY", ""),
            lookup_depth=int(self.config.get("ANYRUN_LOOKUP_DEPTH", 180)),
        )
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
        from app.services.net_utils import is_external_ip

        if not is_external_ip(ip):
            return {"skipped": "non-routable or internal address — no OSINT lookup"}
        results = {}
        for provider, client, method in [
            ("virustotal", self.vt, "lookup_ip"),
            ("abuseipdb", self.abuse, "lookup_ip"),
            ("geo", self.geo, "lookup_ip"),
            ("whois", self.whois, "reverse_dns"),
            ("internetdb", self.internetdb, "lookup_ip"),
            ("otx", self.otx, "lookup_ip"),
            ("greynoise", self.greynoise, "lookup_ip"),
            ("shodan", self.shodan_api, "lookup_ip"),
            ("pulsedive", self.pulsedive, "lookup_ip"),
            ("ipinfo", self.ipinfo, "lookup_ip"),
            ("threatfox", self.threatfox, "lookup_ip"),
            ("anyrun", self.anyrun, "lookup_ip"),
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
                err = str(exc)
                if "event loop" in err.lower() and provider == "virustotal":
                    try:
                        data = await getattr(client, method)(ip)
                        if data:
                            results[provider] = data
                            self._set_cache(provider, "ip", ip, data)
                            continue
                    except Exception as retry_exc:
                        err = str(retry_exc)
                results[provider] = {"error": err}
        return results

    async def _enrich_domain(self, domain: str) -> dict:
        results = {}
        for provider, client, method in [
            ("virustotal", self.vt, "lookup_domain"),
            ("whois", self.whois, "lookup_domain"),
            ("otx", self.otx, "lookup_domain"),
            ("crtsh", self.crtsh, "lookup_domain"),
            ("urlscan", self.urlscan, "lookup_domain"),
            ("anyrun", self.anyrun, "lookup_domain"),
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

    def _compute_verdict(self, enrichment: dict) -> tuple[bool, float, list[dict]]:
        """Return (is_malicious, confidence, verdict_breakdown signals)."""
        malicious_signals = 0
        confidence = 0.0
        signals: list[dict] = []

        vt = enrichment.get("virustotal", {})
        if vt.get("error"):
            signals.append(
                {
                    "provider": "virustotal",
                    "triggered": False,
                    "reason": f"lookup failed: {vt.get('error')}",
                    "raw": vt,
                }
            )
        elif vt and "malicious" in vt:
            mal = int(vt.get("malicious", 0))
            triggered = mal > 2
            if triggered:
                malicious_signals += 1
                confidence += 0.4
            signals.append(
                {
                    "provider": "virustotal",
                    "triggered": triggered,
                    "reason": (
                        f"{mal} malicious engines (threshold >2 met)"
                        if triggered
                        else f"{mal} malicious engines (threshold >2 not met)"
                    ),
                    "raw": vt,
                }
            )

        abuse = enrichment.get("abuseipdb", {})
        if abuse and "abuseConfidenceScore" in abuse:
            score = int(abuse.get("abuseConfidenceScore", 0))
            triggered = score > 25
            if triggered:
                malicious_signals += 1
                confidence += 0.35
            signals.append(
                {
                    "provider": "abuseipdb",
                    "triggered": triggered,
                    "reason": (
                        f"abuse confidence {score}% (>25% met)"
                        if triggered
                        else f"abuse confidence {score}% (≤25%)"
                    ),
                    "raw": abuse,
                }
            )

        whois = enrichment.get("whois", {})
        if whois and whois.get("newly_registered"):
            malicious_signals += 1
            confidence += 0.25
            signals.append(
                {
                    "provider": "whois",
                    "triggered": True,
                    "reason": "newly registered domain (<30 days)",
                    "raw": whois,
                }
            )
        elif whois:
            signals.append(
                {
                    "provider": "whois",
                    "triggered": False,
                    "reason": "domain age OK or IP rDNS only",
                    "raw": whois,
                }
            )

        otx = enrichment.get("otx", {})
        if otx and "pulse_count" in otx:
            pulses = int(otx.get("pulse_count", 0))
            triggered = pulses > 2
            if triggered:
                malicious_signals += 1
                confidence += 0.25
            signals.append(
                {
                    "provider": "otx",
                    "triggered": triggered,
                    "reason": (
                        f"pulse_count={pulses} (>2 met)"
                        if triggered
                        else f"pulse_count={pulses} (≤2)"
                    ),
                    "raw": otx,
                }
            )

        anyrun = enrichment.get("anyrun", {})
        if anyrun and "threat_level" in anyrun:
            level = int(anyrun.get("threat_level", 0))
            triggered = level >= 2
            if level == 1:
                confidence += 0.15
            if triggered:
                malicious_signals += 1
                confidence += 0.35
            signals.append(
                {
                    "provider": "anyrun",
                    "triggered": triggered,
                    "reason": (
                        f"verdict={anyrun.get('verdict')} (threat_level={level})"
                    ),
                    "raw": anyrun,
                }
            )

        greynoise = enrichment.get("greynoise", {})
        if greynoise:
            cls = greynoise.get("classification")
            triggered = cls == "malicious"
            if triggered:
                malicious_signals += 1
                confidence += 0.3
            elif greynoise.get("riot") or cls == "benign":
                confidence = max(0.0, confidence - 0.2)
            signals.append(
                {
                    "provider": "greynoise",
                    "triggered": triggered,
                    "reason": f"classification={cls or 'unknown'}",
                    "raw": greynoise,
                }
            )

        idb = enrichment.get("internetdb", {})
        if idb:
            vulns = idb.get("vulns") or []
            if vulns:
                confidence += 0.1
            signals.append(
                {
                    "provider": "internetdb",
                    "triggered": False,
                    "reason": f"{len(vulns)} known vulns (confidence boost only)",
                    "raw": idb,
                }
            )

        geo = enrichment.get("geo", {})
        if geo:
            signals.append(
                {
                    "provider": "geo",
                    "triggered": False,
                    "reason": "geolocation context only",
                    "raw": geo,
                }
            )

        crt = enrichment.get("crtsh", {})
        if crt:
            signals.append(
                {
                    "provider": "crtsh",
                    "triggered": False,
                    "reason": f"{crt.get('cert_count', 0)} certificates",
                    "raw": crt,
                }
            )

        is_malicious = malicious_signals > 0
        confidence = min(1.0, confidence)
        return is_malicious, confidence, signals

    async def enrich_observable(self, obs: Observable) -> dict:
        if obs.type == "ip":
            enrichment = await self._enrich_ip(obs.value)
        elif obs.type == "domain":
            enrichment = await self._enrich_domain(obs.value)
        else:
            enrichment = {}

        is_malicious, confidence, breakdown = self._compute_verdict(enrichment)
        return {
            "enrichment_json": enrichment,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "verdict_breakdown": breakdown,
            "status": "complete" if enrichment else "error",
        }

    async def lookup_target(self, target_type: str, value: str) -> dict:
        """On-demand lookup with full payloads and verdict breakdown."""
        if target_type == "ip":
            enrichment = await self._enrich_ip(value)
        elif target_type == "domain":
            enrichment = await self._enrich_domain(value)
        else:
            enrichment = {}
        is_malicious, confidence, breakdown = self._compute_verdict(enrichment)
        return {
            "type": target_type,
            "value": value,
            "enrichment_json": enrichment,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "verdict_breakdown": breakdown,
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
        from app.services.enrichment.async_runner import run_async

        return run_async(self.enrich_all(analysis_id, progress_callback))


def get_orchestrator():
    return EnrichmentOrchestrator(dict(current_app.config))
