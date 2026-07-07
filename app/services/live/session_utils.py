"""Resolve active live ML session for triage and alerts."""

from __future__ import annotations


def resolve_live_session_id(config: dict, session_id: str | None = None) -> str | None:
    """Best-effort session id: explicit arg → LLM triage → capture → latest live session."""
    if session_id:
        return str(session_id).strip() or None

    try:
        from app.services.live.live_packet_llm import llm_packet_analysis_status

        st = llm_packet_analysis_status()
        if st.get("session_id"):
            return st["session_id"]
    except Exception:
        pass

    try:
        from app.services.capture import orchestrator as capture_orchestrator

        sid = capture_orchestrator.get_ml_session_id(config)
        if sid:
            return sid
    except Exception:
        pass

    try:
        from app.services.live.monitor import monitor_status
        from app.services.streams import get_session_store

        store = get_session_store()
        if store:
            running = store.find_running()
            if running and monitor_status(running["id"]).get("running"):
                return running["id"]
            recent = store.list_recent(limit=1)
            if recent and recent[0].get("status") == "running":
                return recent[0]["id"]
    except Exception:
        pass

    return None
