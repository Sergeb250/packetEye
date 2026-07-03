"""Parse Suricata EVE JSON in JSONL, array, or pretty-printed formats."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

_ARRAY_FRAME = frozenset("[],)")


def normalize_eve_event(raw: Any) -> dict | None:
    """Coerce parsed JSON into a single EVE event dict."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                inner = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            return inner if isinstance(inner, dict) else None
    return None


def _yield_events(data: Any) -> Iterator[dict]:
    if isinstance(data, dict):
        event = normalize_eve_event(data)
        if event:
            yield event
    elif isinstance(data, list):
        for item in data:
            event = normalize_eve_event(item)
            if event:
                yield event


def iter_eve_events_from_text(text: str) -> Iterator[dict]:
    """Yield EVE event dicts from JSONL, a JSON array, or pretty-printed objects."""
    text = text.strip()
    if not text:
        return

    if text[0] in "[{":
        try:
            yield from _yield_events(json.loads(text))
            return
        except json.JSONDecodeError:
            pass

    seen = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line in _ARRAY_FRAME:
            continue
        line = line.rstrip(",").strip()
        if not line or line in _ARRAY_FRAME:
            continue
        try:
            event = normalize_eve_event(json.loads(line))
        except json.JSONDecodeError:
            continue
        if event:
            seen += 1
            yield event

    if seen:
        return

    for match in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text):
        try:
            event = normalize_eve_event(json.loads(match.group()))
        except json.JSONDecodeError:
            continue
        if event:
            yield event


def iter_eve_events(path: Path) -> Iterator[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    yield from iter_eve_events_from_text(text)


def summarize_eve_event_types(events: Iterator[dict]) -> dict[str, int]:
    counts = {"flow_events": 0, "alert_events": 0, "other_events": 0}
    for event in events:
        etype = event.get("event_type", "unknown")
        if etype == "flow":
            counts["flow_events"] += 1
        elif etype == "alert":
            counts["alert_events"] += 1
        else:
            counts["other_events"] += 1
    return counts
