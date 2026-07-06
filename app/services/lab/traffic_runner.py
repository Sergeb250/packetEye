"""Background lab traffic generator with live log streaming."""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

from app.services.lab.patterns import ALL_LAB_PATTERNS, PATTERN_CIC_LABELS

logger = logging.getLogger(__name__)

DEFAULT_ROTATE_SEC = 8

_state: dict = {
    "process": None,
    "thread": None,
    "log": deque(maxlen=400),
    "running": False,
    "patterns": [],
    "interface": "",
    "current_pattern": None,
    "pattern_started_at": None,
    "rotate_sec": DEFAULT_ROTATE_SEC,
    "last_error": None,
    "started_at": None,
}

_STATUS_RE = re.compile(r"^STATUS:\s*(\{.*\})\s*$")
_PATTERN_RE = re.compile(r"^\[(\w+)\]")


def _append_log(line: str) -> None:
    line = (line or "").rstrip()
    if not line:
        return
    _state["log"].append(line)
    m = _STATUS_RE.match(line)
    if m:
        try:
            payload = json.loads(m.group(1))
            if payload.get("pattern"):
                _state["current_pattern"] = payload["pattern"]
                _state["pattern_started_at"] = payload.get("started_at") or time.time()
            if payload.get("error"):
                _state["last_error"] = payload["error"]
        except json.JSONDecodeError:
            pass
        return
    pm = _PATTERN_RE.match(line)
    if pm:
        _state["current_pattern"] = pm.group(1)
        _state["pattern_started_at"] = time.time()


def _reader_thread(proc: subprocess.Popen) -> None:
    try:
        if proc.stdout:
            for line in proc.stdout:
                _append_log(line)
                if proc.poll() is not None:
                    break
    except Exception as exc:
        _state["last_error"] = str(exc)
        _append_log(f"[runner] {exc}")
    finally:
        _state["running"] = False
        code = proc.poll()
        if code and code != 0:
            _state["last_error"] = _state.get("last_error") or f"Generator exited with code {code}"
        _append_log(f"[lab] generator exited (code {code})")


def _pattern_rows() -> list[dict]:
    patterns = _state.get("patterns") or []
    current = _state.get("current_pattern")
    started = _state.get("pattern_started_at")
    now = time.time()
    rows = []
    if not patterns:
        return rows
    if current and current in patterns:
        idx = patterns.index(current)
    elif current:
        idx = 0
    else:
        idx = -1
    for i, name in enumerate(patterns):
        if current == name:
            status = "active"
            elapsed = round(now - started, 1) if started else 0
        elif idx >= 0 and i < idx:
            status = "done"
            elapsed = _state.get("rotate_sec", DEFAULT_ROTATE_SEC)
        elif idx >= 0 and i == (idx + 1) % len(patterns) and current:
            status = "queued"
            elapsed = 0
        else:
            status = "queued" if current else "pending"
            elapsed = 0
        rows.append({
            "pattern": name,
            "cic_label": PATTERN_CIC_LABELS.get(name, name),
            "status": status,
            "elapsed_sec": elapsed,
        })
    return rows


def _resolve_pattern_arg(patterns: list[str] | None) -> tuple[str, list[str]]:
    """Return (cli_pattern_arg, stored_pattern_list)."""
    if not patterns or patterns == ["all"] or (len(patterns) == 1 and patterns[0].lower() == "all"):
        return "all", list(ALL_LAB_PATTERNS)
    return ",".join(patterns), list(patterns)


def start_lab_traffic(
    script_path: Path,
    patterns: list[str] | None,
    interface: str,
    rotate_sec: int | None = None,
) -> dict:
    if _state.get("running") and _state.get("process"):
        return {"ok": False, "error": "Lab generator already running. Stop it first."}
    if not script_path.is_file():
        return {"ok": False, "error": f"Script not found: {script_path}"}

    pattern_cli, pattern_list = _resolve_pattern_arg(patterns)
    rotate = int(rotate_sec or _state.get("rotate_sec") or DEFAULT_ROTATE_SEC)

    _state["log"].clear()
    _state["last_error"] = None
    _state["current_pattern"] = None
    _state["pattern_started_at"] = None
    cmd = [
        sys.executable,
        str(script_path),
        "--interface", interface,
        "--forever",
        "--pattern", pattern_cli,
        "--rotate-sec", str(rotate),
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc), "hint": "Ensure Scapy is installed and run as root on Linux."}

    time.sleep(0.3)
    if proc.poll() is not None:
        err_lines = []
        if proc.stdout:
            err_lines = proc.stdout.read().splitlines()
        err_text = "\n".join(err_lines[-5:]) if err_lines else f"exit {proc.returncode}"
        hint = "pip install scapy" if "scapy" in err_text.lower() else "Run as root: sudo python run.py"
        _state["last_error"] = err_text
        return {"ok": False, "error": err_text, "hint": hint}

    _state.update({
        "process": proc,
        "running": True,
        "patterns": pattern_list,
        "interface": interface,
        "started_at": time.time(),
        "rotate_sec": rotate,
    })
    _append_log(f"[lab] started patterns={pattern_cli} iface={interface} rotate={rotate}s")
    thread = threading.Thread(target=_reader_thread, args=(proc,), daemon=True, name="lab-traffic")
    _state["thread"] = thread
    thread.start()
    return {"ok": True, "patterns": pattern_list, "interface": interface, "pid": proc.pid, "rotate_sec": rotate}


def stop_lab_traffic() -> dict:
    proc = _state.get("process")
    if not proc or proc.poll() is not None:
        _state.update({"process": None, "running": False, "current_pattern": None})
        return {"ok": True, "message": "Lab generator was not running."}
    try:
        proc.terminate()
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    _state.update({
        "process": None,
        "running": False,
        "current_pattern": None,
        "pattern_started_at": None,
    })
    _append_log("[lab] stopped by user")
    return {"ok": True, "message": "Lab generator stopped."}


def lab_status() -> dict:
    proc = _state.get("process")
    running = bool(proc and proc.poll() is None)
    _state["running"] = running
    if not running and proc and proc.returncode not in (None, 0, -15):
        _state["last_error"] = _state.get("last_error") or f"Process exited (code {proc.returncode})"
    return {
        "running": running,
        "patterns": _state.get("patterns") or [],
        "patterns_queue": _pattern_rows(),
        "interface": _state.get("interface") or "",
        "pid": proc.pid if running and proc else None,
        "current_pattern": _state.get("current_pattern"),
        "pattern_started_at": _state.get("pattern_started_at"),
        "rotate_sec": _state.get("rotate_sec", DEFAULT_ROTATE_SEC),
        "started_at": _state.get("started_at"),
        "last_error": _state.get("last_error"),
        "log": list(_state.get("log") or []),
    }
