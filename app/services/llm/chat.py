"""SOC chatbot — full JSON context for traffic, flows, alerts, and OSINT."""

from __future__ import annotations

import logging

from app.services.llm.context_builder import build_rich_context
from app.services.llm.ensemble import get_llm_ensemble

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are packetEye's SOC analyst assistant embedded in a live network security dashboard.
You analyze PCAP/live capture data: Suricata signatures, ML anomaly scores (0–10, boundary 5.0), flows, DNS/TLS/HTTP
metadata, and OSINT enrichment JSON.

You receive FULL structured JSON context (flows, findings, observables, EVE events, packet summaries).
Use ALL relevant fields in your answer — cite specific IPs, ports, scores, signatures, and enrichment results.

Output format — use GitHub-flavored Markdown:
- **Headings** (##) to structure the answer
- **Markdown tables** for IOCs, flows, timeline, severity breakdown (preferred over bullet lists for tabular data)
- **Bold** for key verdicts and priorities
- **Numbered lists** for response steps (containment → investigate → escalate)
- **Mermaid diagrams** when they clarify attack path or traffic flow, e.g.:
  ```mermaid
  flowchart LR
    A[Internal host] -->|TCP 443| B[External IP]
  ```
  or sequenceDiagram for beaconing/C2 patterns
- Keep prose concise — analysts read this under time pressure

Rules:
- Ground every claim in the provided JSON. If data is missing, say so — never invent IPs or events.
- Distinguish ML anomalies vs Suricata signatures vs correlated hits.
- Flag likely false positives (private/multicast destinations, SSDP, mDNS, DNS to resolvers).
- For "what should I do", give ordered, actionable SOC playbooks."""

MAX_MESSAGE_CHARS = 4000


def chat(
    config: dict,
    message: str,
    history: list[dict] | None = None,
    analysis_id: str | None = None,
    finding_id: str | None = None,
    flow_id: str | None = None,
    context_payload: dict | None = None,
) -> dict:
    message = str(message or "").strip()[:MAX_MESSAGE_CHARS]
    if not message:
        return {"ok": False, "error": "Empty message."}
    if not config.get("LLM_ENABLED", True):
        return {"ok": False, "error": "LLM is disabled (LLM_ENABLED=false)."}
    if not (config.get("LLM_API_KEY") or config.get("NVIDIA_API_KEY")):
        return {"ok": False, "error": "No LLM API key configured. Set NVIDIA_API_KEY in .env."}

    max_ctx = int(config.get("CHATBOT_MAX_CONTEXT_CHARS", 32000))
    context = build_rich_context(
        analysis_id=analysis_id,
        finding_id=finding_id,
        flow_id=flow_id,
        client_payload=context_payload,
        max_chars=max_ctx,
    )

    max_history = int(config.get("CHATBOT_MAX_HISTORY", 10))
    transcript_lines = []
    for turn in (history or [])[-max_history:]:
        role = "Analyst" if turn.get("role") == "user" else "Assistant"
        transcript_lines.append(f"{role}: {str(turn.get('content', ''))[:1200]}")
    transcript = "\n".join(transcript_lines)

    user_prompt = (
        f"=== INVESTIGATION CONTEXT (JSON) ===\n{context}\n\n"
        + (f"=== CONVERSATION SO FAR ===\n{transcript}\n\n" if transcript else "")
        + f"=== ANALYST QUESTION ===\n{message}\n\n"
        + "Respond in Markdown with tables and mermaid diagrams where they help the SOC analyst."
    )

    try:
        ensemble = get_llm_ensemble(dict(config))
        raw = ensemble.complete_text(SYSTEM_PROMPT, user_prompt, temperature=0.3)
    except Exception as exc:
        logger.exception("Chatbot completion failed")
        return {"ok": False, "error": f"LLM request failed: {exc}"}

    reply = (raw or "").strip()
    if not reply or reply == "{}":
        return {"ok": False, "error": "The LLM returned no answer — check the API key and model."}
    return {"ok": True, "reply": reply, "format": "markdown"}
