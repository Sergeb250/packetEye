"""Global LLM call gate — shared concurrency, spacing, and provider backoff."""

from __future__ import annotations

import logging
import re
import threading
import time

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_last_call_at = 0.0
_backoff_until: dict[str, float] = {"nvidia": 0.0, "openrouter": 0.0, "default": 0.0}

# Default 1 concurrent call — avoids NVIDIA 429 when primary+secondary fire together.
_MAX_CONCURRENT = int(__import__("os").environ.get("LLM_MAX_CONCURRENT", "1"))
_MIN_INTERVAL = float(__import__("os").environ.get("LLM_MIN_CALL_INTERVAL_SEC", "0.75"))
_semaphore = threading.Semaphore(_MAX_CONCURRENT)


def _provider_key(provider_label: str) -> str:
    label = (provider_label or "").lower()
    if "openrouter" in label:
        return "openrouter"
    if "zai" in label or "zhipu" in label or "glm" in label:
        return "zai"
    if "nvidia" in label or "nim" in label:
        return "nvidia"
    return "default"


def split_budget(total: int, providers: int) -> int:
    """Split a shared output-token budget across N simultaneous model calls."""
    n = max(1, providers)
    return max(64, int(total) // n)


def wait_if_backoff(provider_label: str = "nvidia") -> None:
    key = _provider_key(provider_label)
    with _lock:
        until = _backoff_until.get(key, 0.0)
    if until > time.monotonic():
        delay = until - time.monotonic()
        logger.debug("LLM backoff %s sleeping %.1fs", key, delay)
        time.sleep(delay)


def note_failure(provider_label: str, exc: Exception | str) -> float:
    """Record provider failure; return suggested retry delay seconds."""
    msg = str(exc).lower()
    delay = 0.0
    if "429" in msg or "too many requests" in msg:
        delay = 10.0
    elif "402" in msg or "credits" in msg or "max_tokens" in msg:
        delay = 5.0
        match = re.search(r"can only afford (\d+)", msg)
        if match:
            delay = 2.0
    if delay:
        key = _provider_key(provider_label)
        with _lock:
            _backoff_until[key] = time.monotonic() + delay
        logger.warning("LLM %s backoff %.0fs after: %s", key, delay, str(exc)[:120])
    return delay


def affordable_max_tokens(exc: Exception | str, requested: int) -> int | None:
    """Parse OpenRouter 402 'can only afford N' and return a safe max_tokens."""
    msg = str(exc)
    match = re.search(r"can only afford (\d+)", msg)
    if match:
        afford = int(match.group(1))
        return max(64, min(requested, afford - 16))
    return None


class llm_call_slot:
    """Context manager: limits concurrent LLM calls and enforces min spacing."""

    def __init__(self, provider_label: str = "nvidia"):
        self.provider_label = provider_label

    def __enter__(self):
        wait_if_backoff(self.provider_label)
        _semaphore.acquire()
        global _last_call_at
        with _lock:
            gap = _MIN_INTERVAL - (time.monotonic() - _last_call_at)
        if gap > 0:
            time.sleep(gap)
        return self

    def __exit__(self, exc_type, exc, tb):
        global _last_call_at
        with _lock:
            _last_call_at = time.monotonic()
        _semaphore.release()
        return False
