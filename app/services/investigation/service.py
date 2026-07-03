"""Alert-driven OSINT investigation.

Instead of bulk-enriching every observable at ingest, analysts (or the
AUTO_INVESTIGATE_LIVE policy) trigger OSINT lookups — VirusTotal, AbuseIPDB,
WHOIS/reverse DNS, GeoIP — for the IPs/domains behind a specific finding.
Results are persisted on Finding.evidence["investigation"] and shown in the UI.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import threading
from datetime import datetime, timezone

from app.extensions import db
from app.models.analysis import Finding
from app.services.enrichment.orchestrator import EnrichmentOrchestrator

logger = logging.getLogger(__name__)

MAX_TARGETS_PER_INVESTIGATION = 6


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def _looks_like_domain(value: str) -> bool:
    v = str(value).strip().lower()
    return bool(v) and "." in v and not _is_ip(v) and " " not in v and len(v) <= 253


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def extract_targets(finding: Finding) -> list[dict]:
    """IPs/domains worth investigating from a finding's evidence + flow."""
    targets: list[dict] = []
    seen: set[str] = set()

    def add(kind: str, value) -> None:
        v = str(value or "").strip()
        if not v or v in seen or len(targets) >= MAX_TARGETS_PER_INVESTIGATION:
            return
        if kind == "ip" and not _is_ip(v):
            return
        if kind == "domain" and not _looks_like_domain(v):
            return
        seen.add(v)
        targets.append({"type": kind, "value": v, "public": _is_public_ip(v) if kind == "ip" else True})

    evidence = finding.evidence or {}
    for key in ("src_ip", "dst_ip", "dest_ip", "ip"):
        add("ip", evidence.get(key))
    for key in ("domain", "hostname", "apex", "dns_query", "tls_sni"):
        add("domain", evidence.get(key))

    if finding.flow_id:
        from app.models.analysis import Flow

        flow = Flow.query.get(finding.flow_id)
        if flow:
            add("ip", flow.src_ip)
            add("ip", flow.dst_ip)
            add("domain", flow.tls_sni)
            for q in (flow.dns_queries or [])[:2]:
                add("domain", q)

    return targets


class InvestigationService:
    def __init__(self, config: dict):
        self.config = dict(config)
        self.orchestrator = EnrichmentOrchestrator(self.config)

    async def _lookup(self, target: dict) -> dict:
        if target["type"] == "ip":
            if not target.get("public", True):
                return {"skipped": "private address — no OSINT lookup"}
            return await self.orchestrator._enrich_ip(target["value"])
        return await self.orchestrator._enrich_domain(target["value"])

    async def _gather(self, targets: list[dict]) -> dict:
        results = {}
        for target in targets:  # sequential — respects provider rate limits
            enrichment = await self._lookup(target)
            entry = {"type": target["type"], "results": enrichment}
            if "skipped" not in enrichment:
                is_malicious, confidence = self.orchestrator._compute_verdict(enrichment)
                entry["is_malicious"] = is_malicious
                entry["confidence"] = round(confidence, 2)
            results[target["value"]] = entry
        return results

    def run(self, targets: list[dict]) -> dict:
        """Synchronous OSINT fan-out for a small set of targets."""
        if not targets:
            return {}
        return asyncio.run(self._gather(targets))


def _set_investigation(finding: Finding, payload: dict) -> None:
    # Reassign the JSON column so SQLAlchemy notices the change.
    evidence = dict(finding.evidence or {})
    evidence["investigation"] = payload
    finding.evidence = evidence
    db.session.commit()


def _sync_observables(finding: Finding, results: dict) -> None:
    """Write investigation results onto Observable rows so the threat map,
    IOC tables, and report exports fill in progressively per alert."""
    from app.models.analysis import Observable

    for value, entry in results.items():
        enrichment = entry.get("results") or {}
        if "skipped" in enrichment:
            continue
        obs = Observable.query.filter_by(
            analysis_id=finding.analysis_id, type=entry.get("type"), value=value
        ).first()
        if not obs:
            obs = Observable(
                analysis_id=finding.analysis_id,
                type=entry.get("type"),
                value=value,
                occurrence_count=1,
            )
            db.session.add(obs)
        merged = dict(obs.enrichment_json or {})
        merged.update(enrichment)
        obs.enrichment_json = merged
        obs.enrichment_status = "complete"
        if "is_malicious" in entry:
            obs.is_malicious = bool(entry["is_malicious"])
            obs.confidence = max(float(obs.confidence or 0), float(entry.get("confidence") or 0))
    db.session.commit()


def investigate_finding_sync(config: dict, finding_id: str) -> dict:
    """Run an investigation for a finding and persist results. Blocking."""
    finding = Finding.query.get(finding_id)
    if not finding:
        return {"ok": False, "error": "Finding not found"}

    targets = extract_targets(finding)
    if not targets:
        result = {
            "status": "complete",
            "at": datetime.now(timezone.utc).isoformat(),
            "targets": {},
            "note": "No public IPs or domains found in this finding's evidence.",
        }
        _set_investigation(finding, result)
        return {"ok": True, "investigation": result}

    _set_investigation(
        finding,
        {"status": "running", "at": datetime.now(timezone.utc).isoformat(), "targets": {}},
    )

    try:
        service = InvestigationService(config)
        results = service.run(targets)
    except Exception as exc:
        logger.exception("Investigation failed for finding %s", finding_id)
        result = {
            "status": "failed",
            "at": datetime.now(timezone.utc).isoformat(),
            "error": str(exc),
        }
        _set_investigation(Finding.query.get(finding_id), result)
        return {"ok": False, "error": str(exc)}

    malicious = [v for v in results.values() if v.get("is_malicious")]
    result = {
        "status": "complete",
        "at": datetime.now(timezone.utc).isoformat(),
        "targets": results,
        "malicious_count": len(malicious),
    }

    finding = Finding.query.get(finding_id)  # re-fetch: session may have rolled over
    _set_investigation(finding, result)
    try:
        _sync_observables(finding, results)
    except Exception:
        logger.exception("Observable sync failed for finding %s", finding_id)

    # Malicious OSINT verdict on an already-flagged finding is high-signal.
    if malicious and finding.severity in ("low", "medium"):
        finding.severity = "high"
        finding.severity_score = max(finding.severity_score or 0, 8.0)
        db.session.commit()

    return {"ok": True, "investigation": result}


def kickoff_investigation(app, finding_id: str) -> bool:
    """Investigate in a background thread so the API returns immediately."""

    def _run():
        with app.app_context():
            try:
                investigate_finding_sync(dict(app.config), finding_id)
            except Exception:
                logger.exception("Background investigation failed for %s", finding_id)

    thread = threading.Thread(target=_run, name=f"investigate-{finding_id[:8]}", daemon=True)
    thread.start()
    return True


def get_investigation(finding_id: str) -> dict:
    finding = Finding.query.get(finding_id)
    if not finding:
        return {"ok": False, "error": "Finding not found"}
    investigation = (finding.evidence or {}).get("investigation")
    return {
        "ok": True,
        "finding_id": finding_id,
        "title": finding.title,
        "severity": finding.severity,
        "investigation": investigation or {"status": "none"},
    }
