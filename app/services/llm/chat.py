"""SOC chatbot — lets analysts interrogate findings and reports in plain language.

Context is metadata-only (findings, scores, observables); raw packet payloads
are never sent to the LLM.
"""

from __future__ import annotations

import logging

from app.models.analysis import Analysis, Finding, Observable
from app.services.llm.provider import get_provider

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are packetEye's SOC analyst assistant embedded in a network forensics dashboard.
You help analysts understand detection findings (YAML rules, Isolation Forest ML anomalies with 0-10
calibrated scores where 5.0 is the decision boundary, Suricata signatures, and correlations), interpret
MITRE ATT&CK mappings, judge severity, and plan response steps (containment, investigation, escalation).

Rules:
- Ground every answer in the provided analysis context. If the context does not contain the answer,
  say so plainly — never invent IPs, signatures, or events.
- Be concise and practical: an analyst is reading this mid-investigation.
- When asked "what should I do", give concrete next steps ordered by priority.
- Plain text / light markdown only."""

MAX_FINDINGS_IN_CONTEXT = 15
MAX_MESSAGE_CHARS = 2000


def build_context(analysis_id: str | None = None, finding_id: str | None = None) -> str:
    """Metadata-only investigation context for the LLM."""
    parts: list[str] = []

    finding = Finding.query.get(finding_id) if finding_id else None
    if finding and not analysis_id:
        analysis_id = finding.analysis_id

    analysis = Analysis.query.get(analysis_id) if analysis_id else None
    if analysis:
        parts.append(
            f"ANALYSIS: {analysis.analysis_name or analysis.filename} | source={analysis.source or 'pcap'} "
            f"| status={analysis.status} | risk_score={analysis.risk_score} "
            f"| flows={analysis.total_flows} | findings={analysis.total_findings}"
        )
        summary = (analysis.report_json or {}).get("executive_summary") or (
            analysis.summary_json or {}
        ).get("executive_summary")
        if summary:
            parts.append(f"EXECUTIVE SUMMARY: {str(summary)[:1200]}")

    if finding:
        evidence = finding.evidence or {}
        investigation = evidence.get("investigation") or {}
        parts.append(
            "FOCUSED FINDING:\n"
            f"- title: {finding.title}\n"
            f"- severity: {finding.severity} (score {finding.severity_score})\n"
            f"- source: {finding.source} | rule: {finding.rule_id}\n"
            f"- description: {(finding.llm_explanation or finding.description or '')[:800]}\n"
            f"- mitre: {finding.mitre_tactic or '—'} / {finding.mitre_technique or '—'}\n"
            f"- evidence: {str({k: v for k, v in evidence.items() if k != 'investigation'})[:800]}\n"
            f"- osint investigation: {str(investigation)[:1200] if investigation else 'not run yet'}"
        )

    if not analysis and not finding:
        # No page context (e.g. dashboard) — give a fleet-wide overview.
        recent = Analysis.query.order_by(Analysis.created_at.desc()).limit(8).all()
        if recent:
            parts.append(
                "RECENT ANALYSES:\n"
                + "\n".join(
                    f"- {a.analysis_name or a.filename} | source={a.source or 'pcap'} | "
                    f"status={a.status} | risk={a.risk_score} | findings={a.total_findings}"
                    for a in recent
                )
            )
        latest = (
            Finding.query.filter_by(is_false_positive=False)
            .order_by(Finding.created_at.desc())
            .limit(MAX_FINDINGS_IN_CONTEXT)
            .all()
        )
        if latest:
            parts.append(
                "LATEST FINDINGS (all analyses):\n"
                + "\n".join(f"- [{f.severity}] ({f.source}) {f.title}" for f in latest)
            )

    if analysis:
        findings = (
            Finding.query.filter_by(analysis_id=analysis.id, is_false_positive=False)
            .order_by(Finding.severity_score.desc())
            .limit(MAX_FINDINGS_IN_CONTEXT)
            .all()
        )
        if findings:
            lines = [
                f"- [{f.severity}] ({f.source}) {f.title} | evidence: "
                + str({k: v for k, v in (f.evidence or {}).items() if k != "investigation"})[:200]
                for f in findings
                if not finding or f.id != finding.id
            ]
            if lines:
                parts.append("TOP FINDINGS:\n" + "\n".join(lines))

        malicious = (
            Observable.query.filter_by(analysis_id=analysis.id, is_malicious=True).limit(10).all()
        )
        if malicious:
            parts.append(
                "MALICIOUS OBSERVABLES:\n"
                + "\n".join(f"- {o.type}: {o.value} (confidence {o.confidence})" for o in malicious)
            )

    return "\n\n".join(parts) if parts else "No analysis context available."


def chat(config: dict, message: str, history: list[dict] | None = None,
         analysis_id: str | None = None, finding_id: str | None = None) -> dict:
    message = str(message or "").strip()[:MAX_MESSAGE_CHARS]
    if not message:
        return {"ok": False, "error": "Empty message."}
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM is disabled (LLM_ENABLED=false)."}
    if not (config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")):
        return {"ok": False, "error": "No LLM API key configured. Set NVIDIA_API_KEY in .env."}

    context = build_context(analysis_id=analysis_id, finding_id=finding_id)

    max_history = int(config.get("CHATBOT_MAX_HISTORY", 10))
    transcript_lines = []
    for turn in (history or [])[-max_history:]:
        role = "Analyst" if turn.get("role") == "user" else "Assistant"
        transcript_lines.append(f"{role}: {str(turn.get('content', ''))[:800]}")
    transcript = "\n".join(transcript_lines)

    user_prompt = (
        f"=== INVESTIGATION CONTEXT ===\n{context}\n\n"
        + (f"=== CONVERSATION SO FAR ===\n{transcript}\n\n" if transcript else "")
        + f"=== ANALYST QUESTION ===\n{message}"
    )

    try:
        provider = get_provider(dict(config))
        raw = provider.complete(SYSTEM_PROMPT, user_prompt, temperature=0.3)
    except Exception as exc:
        logger.exception("Chatbot completion failed")
        return {"ok": False, "error": f"LLM request failed: {exc}"}

    reply = (raw or "").strip()
    if not reply or reply == "{}":
        return {"ok": False, "error": "The LLM returned no answer — check the API key and model."}
    return {"ok": True, "reply": reply}
