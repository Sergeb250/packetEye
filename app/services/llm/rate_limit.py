"""Global LLM call gate — shared concurrency, spacing, and provider backoff."""

from __future__ import annotations

import logging
import re
import threading
import time

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_last_call_at = 0.0
_backoff_until: dict[str, float] = {
    "zai": 0.0,
    "nvidia": 0.0,
    "openrouter": 0.0,
    "default": 0.0,
}
_provider_last_at: dict[str, float] = {}
_provider_sems: dict[str, threading.Semaphore] = {}

# Default 1 concurrent call — avoids NVIDIA 429 when primary+secondary fire together.
_MAX_CONCURRENT = int(__import__("os").environ.get("LLM_MAX_CONCURRENT", "1"))
_MIN_INTERVAL = float(__import__("os").environ.get("LLM_MIN_CALL_INTERVAL_SEC", "0.75"))
_semaphore = threading.Semaphore(_MAX_CONCURRENT)

# Credit exhaustion (OpenRouter 402) does not clear in seconds — park the
# provider instead of hammering it on every live packet.
_CREDIT_BACKOFF_SECONDS = float(__import__("os").environ.get("LLM_402_BACKOFF_SECONDS", "1800"))
# Never sleep a caller for the whole backoff window; long waits belong to
# is_provider_blocked() skipping, not to blocking request/live threads.
_MAX_BACKOFF_SLEEP = 8.0


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
        delay = min(until - time.monotonic(), _MAX_BACKOFF_SLEEP)
        logger.debug("LLM backoff %s sleeping %.1fs", key, delay)
        time.sleep(delay)


def is_provider_blocked(provider_label: str) -> bool:
    """True while the provider sits in a backoff window — callers should skip it."""
    key = _provider_key(provider_label)
    with _lock:
        return _backoff_until.get(key, 0.0) > time.monotonic()


def note_failure(provider_label: str, exc: Exception | str) -> float:
    """Record provider failure; return suggested retry delay seconds."""
    msg = str(exc).lower()
    key = _provider_key(provider_label)
    delay = 0.0
    if "429" in msg or "too many requests" in msg:
        delay = 10.0
    elif "402" in msg or "credits" in msg or "max_tokens" in msg:
        if re.search(r"can only afford (\d+)", msg):
            # Provider retries once with a reduced token budget — keep the
            # window short so that retry is not blocked.
            delay = 2.0
        elif key == "openrouter" and ("402" in msg or "credits" in msg):
            delay = _CREDIT_BACKOFF_SECONDS
        else:
            delay = 5.0
    if delay:
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


class provider_call_slot:
    """Per-provider slot — Z.ai, NVIDIA, and OpenRouter can run in parallel."""

    def __init__(self, provider_label: str = "nvidia"):
        self.key = _provider_key(provider_label)

    def _sem(self) -> threading.Semaphore:
        if self.key not in _provider_sems:
            _provider_sems[self.key] = threading.Semaphore(1)
        return _provider_sems[self.key]

    def __enter__(self):
        wait_if_backoff(self.key)
        self._sem().acquire()
        with _lock:
            gap = _MIN_INTERVAL - (time.monotonic() - _provider_last_at.get(self.key, 0.0))
        if gap > 0:
            time.sleep(gap)
        return self

    def __exit__(self, exc_type, exc, tb):
        with _lock:
            _provider_last_at[self.key] = time.monotonic()
        self._sem().release()
        return False
