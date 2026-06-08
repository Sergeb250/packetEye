"""Prompt templates for LLM analysis."""

SYSTEM_ANALYST = (
    "You are a senior network security analyst. Respond only in valid JSON with the exact schema requested."
)

FINDING_PROMPT = """You are reviewing a finding from an automated network analysis tool.

Finding: {title}
Severity: {severity}
Evidence: {evidence}
Enrichment data: {enrichment}
MITRE mapping: {mitre_tactic} / {mitre_technique}

Provide JSON:
{{"explanation": "2-3 sentences", "recommendation": "specific action", "confidence": "high|medium|low", "confidence_reason": "one sentence"}}"""

EXECUTIVE_SUMMARY_PROMPT = """Summarize this network analysis for a non-technical stakeholder in 3-5 paragraphs.

Analysis stats: {stats}
Top findings: {findings}
Malicious observables: {malicious_observables}

Respond in JSON: {{"summary": "multi-paragraph text"}}"""

HUNT_HYPOTHESES_PROMPT = """Based on these network analysis findings, propose 3-5 threat hunting hypotheses.

Findings: {findings}
Enrichment highlights: {enrichment}

Respond in JSON: {{"hypotheses": [{{"statement": "...", "investigation_steps": ["step1", "step2"]}}]}}"""
