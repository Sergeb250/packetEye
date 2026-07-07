"""Threat narrative generator using LLM."""

import hashlib
import json
import logging

from app.extensions import cache, db
from app.models.analysis import Analysis, Finding, Flow, Observable
from app.services.llm.prompts import (
    EXECUTIVE_SUMMARY_PROMPT,
    FINDING_PROMPT,
    HUNT_HYPOTHESES_PROMPT,
    SYSTEM_REPORT_ANALYST,
)
from app.services.llm.ensemble import get_llm_ensemble
from app.services.llm.tokens import with_tier

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class LLMAnalyst:
    MAX_CONSECUTIVE_FAILURES = 2

    def __init__(self, config: dict):
        report_cfg = with_tier(dict(config), "report")
        report_cfg["LLM_MAX_TOKENS"] = int(
            config.get("LLM_REPORT_MAX_TOKENS", report_cfg.get("LLM_MAX_TOKENS", 2048))
        )
        self.config = report_cfg
        self.ensemble = get_llm_ensemble(report_cfg)
        self.max_calls = int(config.get("LLM_MAX_CALLS_PER_ANALYSIS", 25))
        self.enabled = config.get("LLM_ENABLED", True)
        self._call_count = 0
        self._consecutive_failures = 0

    def _cache_key(self, prefix: str, data: str) -> str:
        h = hashlib.sha256(data.encode()).hexdigest()[:16]
        return f"llm:{prefix}:{h}"

    def _cached_or_call(self, prefix: str, input_data: str, system: str, user: str, temperature: float = 0.2) -> dict:
        if not self.enabled or self._call_count >= self.max_calls:
            return {}

        key = self._cache_key(prefix, input_data)
        try:
            cached = cache.get(key)
            if cached:
                return json.loads(cached) if isinstance(cached, str) else cached
        except Exception:
            pass

        self._call_count += 1
        result = self.ensemble.complete_json(system, user, temperature, cache_prefix=prefix)
        if result:
            self._consecutive_failures = 0
            try:
                cache.set(key, json.dumps(result), timeout=86400)
            except Exception:
                pass
        else:
            # Circuit breaker: a dead/misconfigured LLM API must not stall the
            # pipeline call after call — give up for this analysis.
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                logger.warning(
                    "LLM provider failed %s times in a row — skipping remaining AI enrichment",
                    self._consecutive_failures,
                )
                self.enabled = False
        logger.info("LLM call %s/%s: %s", self._call_count, self.max_calls, prefix)
        return result

    def enrich_findings(self, analysis_id: str, progress_cb=None) -> int:
        findings = (
            Finding.query.filter_by(analysis_id=analysis_id, is_false_positive=False)
            .order_by(Finding.severity_score.desc())
            .all()
        )
        candidates = [
            f for f in findings
            if SEVERITY_ORDER.get(f.severity, 5) <= SEVERITY_ORDER["medium"]
        ][: self.max_calls]
        enriched = 0
        for idx, finding in enumerate(candidates):
            if not self.enabled or self._call_count >= self.max_calls:
                break
            if progress_cb:
                progress_cb(idx + 1, len(candidates))

            evidence = json.dumps(finding.evidence or {}, default=str)
            flow_data = {}
            if finding.flow_id:
                f = Flow.query.get(finding.flow_id)
                if f:
                    flow_data = f.to_dict()
            enrichment = self._get_finding_enrichment(finding)
            user = FINDING_PROMPT.format(
                title=finding.title,
                severity=finding.severity,
                evidence=evidence[:8000],
                flow_json=json.dumps(flow_data, default=str)[:8000],
                enrichment=json.dumps(enrichment, default=str)[:8000],
                mitre_tactic=finding.mitre_tactic or "",
                mitre_technique=finding.mitre_technique or "",
            )
            result = self._cached_or_call(
                f"finding:{finding.id}", user, SYSTEM_REPORT_ANALYST, user, 0.2
            )
            if result:
                finding.llm_explanation = result.get("explanation", finding.description)
                finding.recommendation = result.get("recommendation", finding.recommendation)
                finding.llm_confidence = result.get("confidence")
                enriched += 1

        db.session.commit()
        return enriched

    def _get_finding_enrichment(self, finding: Finding) -> dict:
        evidence = finding.evidence or {}
        ips = []
        if "src_ip" in evidence:
            ips.append(evidence["src_ip"])
        if "dst_ip" in evidence:
            ips.append(evidence["dst_ip"])
        obs = []
        if ips:
            obs = Observable.query.filter(
                Observable.analysis_id == finding.analysis_id,
                Observable.value.in_(ips),
            ).all()
        return {o.value: o.enrichment_json for o in obs}

    def generate_executive_summary(self, analysis_id: str) -> str:
        analysis = Analysis.query.get(analysis_id)
        findings = Finding.query.filter_by(analysis_id=analysis_id, is_false_positive=False).all()
        malicious = Observable.query.filter_by(analysis_id=analysis_id, is_malicious=True).all()

        stats = analysis.summary_json or {}
        findings_summary = [{"title": f.title, "severity": f.severity} for f in findings[:10]]
        user = EXECUTIVE_SUMMARY_PROMPT.format(
            stats=json.dumps(stats, default=str),
            findings=json.dumps(findings_summary),
            malicious_observables=[o.value for o in malicious[:10]],
        )
        result = self._cached_or_call(
            f"exec:{analysis_id}", user, SYSTEM_REPORT_ANALYST, user, 0.3
        )
        return result.get("summary", "Analysis complete. Review findings for details.")

    def generate_hunt_hypotheses(self, analysis_id: str) -> list:
        findings = Finding.query.filter_by(analysis_id=analysis_id, is_false_positive=False).limit(15).all()
        obs = Observable.query.filter_by(analysis_id=analysis_id, is_malicious=True).limit(10).all()

        user = HUNT_HYPOTHESES_PROMPT.format(
            findings=json.dumps([f.to_dict() for f in findings], default=str)[:3000],
            enrichment=json.dumps([o.to_dict() for o in obs], default=str)[:2000],
        )
        result = self._cached_or_call(
            f"hunt:{analysis_id}", user, SYSTEM_REPORT_ANALYST, user, 0.5
        )
        return result.get("hypotheses", [])
