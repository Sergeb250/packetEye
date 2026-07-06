"""Build rich JSON investigation context for SOC chat and LLM analysis."""

from __future__ import annotations

import json
from typing import Any

from app.models.analysis import Analysis, Finding, Flow, Observable

MAX_FINDINGS = 20
MAX_FLOWS = 25
MAX_OBSERVABLES = 40


def truncate_json(obj: Any, max_chars: int = 12000) -> str:
    text = json.dumps(obj, default=str, indent=2, ensure_ascii=False)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 24] + "\n… [truncated for length]"


def _finding_bundle(finding: Finding) -> dict:
    bundle = finding.to_dict()
    if finding.flow_id:
        flow = Flow.query.get(finding.flow_id)
        if flow:
            bundle["flow"] = flow.to_dict()
    evidence = finding.evidence or {}
    ips = {evidence.get("src_ip"), evidence.get("dst_ip")} - {None, ""}
    if ips:
        obs = Observable.query.filter(
            Observable.analysis_id == finding.analysis_id,
            Observable.value.in_(list(ips)),
        ).all()
        bundle["related_observables"] = [o.to_dict() for o in obs]
    inv = evidence.get("investigation")
    if inv:
        bundle["investigation"] = inv
    return bundle


def build_rich_context(
    analysis_id: str | None = None,
    finding_id: str | None = None,
    flow_id: str | None = None,
    client_payload: dict | None = None,
    max_chars: int = 32000,
) -> str:
    """Assemble full JSON context for LLM — flows, findings, observables, live payloads."""
    sections: list[str] = []
    budget = max_chars

    finding = Finding.query.get(finding_id) if finding_id else None
    if finding and not analysis_id:
        analysis_id = finding.analysis_id
    if finding and not flow_id and finding.flow_id:
        flow_id = finding.flow_id

    flow = Flow.query.get(flow_id) if flow_id else None
    if flow and not analysis_id:
        analysis_id = flow.analysis_id

    analysis = Analysis.query.get(analysis_id) if analysis_id else None

    if client_payload:
        block = truncate_json(client_payload, min(8000, budget // 4))
        sections.append(f"=== CLIENT / LIVE RAW CONTEXT (JSON) ===\n{block}")
        budget -= len(block)

    if finding:
        block = truncate_json(_finding_bundle(finding), min(10000, budget // 3))
        sections.append(f"=== FOCUSED FINDING (full JSON) ===\n{block}")
        budget -= len(block)

    if flow and (not finding or flow.id != finding.flow_id):
        block = truncate_json(flow.to_dict(), min(6000, budget // 4))
        sections.append(f"=== FOCUSED FLOW (full JSON) ===\n{block}")
        budget -= len(block)

    if analysis:
        meta = {
            "id": analysis.id,
            "filename": analysis.filename,
            "analysis_name": analysis.analysis_name,
            "source": analysis.source,
            "status": analysis.status,
            "risk_score": analysis.risk_score,
            "total_flows": analysis.total_flows,
            "total_findings": analysis.total_findings,
            "summary_json": analysis.summary_json or {},
            "report_json": analysis.report_json or {},
        }
        block = truncate_json(meta, min(8000, budget // 4))
        sections.append(f"=== ANALYSIS METADATA (JSON) ===\n{block}")
        budget -= len(block)

        findings = (
            Finding.query.filter_by(analysis_id=analysis.id, is_false_positive=False)
            .order_by(Finding.severity_score.desc())
            .limit(MAX_FINDINGS)
            .all()
        )
        if findings:
            payload = [_finding_bundle(f) for f in findings if not finding or f.id != finding.id]
            if payload:
                block = truncate_json(payload, min(12000, budget // 3))
                sections.append(f"=== FINDINGS (full JSON, top {len(payload)}) ===\n{block}")
                budget -= len(block)

        flows = (
            Flow.query.filter_by(analysis_id=analysis.id)
            .order_by(Flow.anomaly_score.desc(), Flow.severity_score.desc())
            .limit(MAX_FLOWS)
            .all()
        )
        if flows:
            block = truncate_json([f.to_dict() for f in flows], min(10000, budget // 3))
            sections.append(f"=== TOP FLOWS BY ANOMALY (full JSON) ===\n{block}")
            budget -= len(block)

        observables = (
            Observable.query.filter_by(analysis_id=analysis.id)
            .order_by(Observable.is_malicious.desc(), Observable.confidence.desc())
            .limit(MAX_OBSERVABLES)
            .all()
        )
        if observables:
            block = truncate_json([o.to_dict() for o in observables], min(8000, budget // 4))
            sections.append(f"=== OBSERVABLES + OSINT ENRICHMENT (full JSON) ===\n{block}")

    if not sections:
        recent = Analysis.query.order_by(Analysis.created_at.desc()).limit(5).all()
        if recent:
            sections.append(
                "=== RECENT ANALYSES ===\n"
                + truncate_json([a.to_dict() for a in recent], 4000)
            )

    return "\n\n".join(sections) if sections else "No analysis context available."
