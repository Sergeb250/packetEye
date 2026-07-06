"""Run async coroutines from sync Flask/Celery code without event-loop conflicts."""

from __future__ import annotations

import asyncio
import threading

_loop: asyncio.AbstractEventLoop | None = None
_loop_thread: threading.Thread | None = None
_init_lock = threading.Lock()


def _ensure_loop() -> asyncio.AbstractEventLoop:
    global _loop, _loop_thread
    with _init_lock:
        if _loop is None or not _loop.is_running():
            _loop = asyncio.new_event_loop()

            def _run() -> None:
                asyncio.set_event_loop(_loop)
                _loop.run_forever()

            _loop_thread = threading.Thread(target=_run, name="enrichment-async", daemon=True)
            _loop_thread.start()
    return _loop


def run_async(coro, timeout: float = 120):
    """Execute *coro* on a dedicated background event loop."""
    loop = _ensure_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=timeout)
