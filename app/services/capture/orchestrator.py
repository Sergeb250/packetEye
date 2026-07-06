"""Dashboard-controlled traffic capture: Suricata (primary) or tcpdump (fallback).

Runs everything on the sensor box — analysts start/stop capture from the
browser, never from a terminal. State is persisted to a JSON file so a Flask
restart can rediscover (and stop) a capture process it started earlier.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from app.services.capture.privileges import (
    build_tcpdump_command,
    chunk_dir_candidates,
    live_capture_privilege_hint,
    prepare_tcpdump_chunk_dir,
    resolve_tcpdump_chunk_dir,
    running_as_root,
    tcpdump_failure_hint,
)

from app.services.live import suricata_manager

logger = logging.getLogger(__name__)

VALID_MODES = ("suricata", "tcpdump")

# In-process handle for a tcpdump we spawned (suricata is handled by
# suricata_manager, which keeps its own handle).
_tcpdump: dict = {"process": None}


def _state_path(config: dict) -> Path:
    return Path(str(config.get("CAPTURE_STATE_DIR") or "data/capture")) / "capture_state.json"


def _read_state(config: dict) -> dict:
    path = _state_path(config)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_state(config: dict, state: dict) -> None:
    path = _state_path(config)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not persist capture state: %s", exc)


def get_ml_session_id(config: dict) -> str | None:
    sid = _read_state(config).get("ml_session_id")
    return str(sid) if sid else None


def set_ml_session_id(config: dict, session_id: str | None) -> None:
    state = _read_state(config)
    if not state:
        return
    if session_id:
        state["ml_session_id"] = session_id
    else:
        state.pop("ml_session_id", None)
    _write_state(config, state)


def _clear_state(config: dict) -> None:
    try:
        _state_path(config).unlink(missing_ok=True)
    except OSError:
        pass


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        import psutil

        return psutil.pid_exists(pid)
    except ImportError:
        pass
    if sys.platform == "win32":
        try:
            import ctypes

            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        except (OSError, AttributeError, ValueError):
            return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _clear_stale_state(config: dict, state: dict, suricata: dict, tcpdump_running: bool) -> dict:
    """Drop persisted capture state when nothing packetEye started is still alive."""
    if not state:
        return state
    mode = state.get("mode")
    managed = bool(suricata.get("managed"))
    pid_alive = _pid_alive(state.get("pid"))
    if managed or tcpdump_running:
        return state
    if mode == "suricata" and not managed and not pid_alive:
        _clear_state(config)
        logger.info("Cleared stale Suricata capture state (process not managed/alive)")
        return {}
    if mode == "tcpdump" and not tcpdump_running and not pid_alive:
        _clear_state(config)
        logger.info("Cleared stale tcpdump capture state")
        return {}
    return state


def _resolve_tcpdump(config: dict) -> str | None:
    binary = str(config.get("TCPDUMP_BIN") or "tcpdump")
    found = shutil.which(binary)
    if found:
        return found
    return binary if Path(binary).is_file() else None


def _chunk_dir(config: dict) -> Path:
    return resolve_tcpdump_chunk_dir(config)


def _chunk_stats(config: dict) -> dict:
    chunk_dir = _chunk_dir(config)
    if not chunk_dir.is_dir():
        return {"dir": str(chunk_dir), "count": 0, "latest": None, "latest_age_seconds": None}
    chunks = sorted(chunk_dir.glob("chunk_*.pcap"), key=lambda p: p.stat().st_mtime)
    latest = chunks[-1] if chunks else None
    return {
        "dir": str(chunk_dir),
        "count": len(chunks),
        "latest": latest.name if latest else None,
        "latest_age_seconds": round(time.time() - latest.stat().st_mtime, 1) if latest else None,
    }


def list_tcpdump_chunks(config: dict) -> list[dict]:
    chunk_dir = _chunk_dir(config)
    if not chunk_dir.is_dir():
        return []
    out = []
    for p in sorted(chunk_dir.glob("chunk_*.pcap"), key=lambda x: x.stat().st_mtime, reverse=True):
        st = p.stat()
        out.append({
            "name": p.name,
            "path": str(p),
            "size_bytes": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        })
    return out[:50]


def start_capture(config: dict, mode: str | None = None, interface: str | None = None) -> dict:
    mode = (mode or str(config.get("CAPTURE_MODE") or "suricata")).strip().lower()
    if mode not in VALID_MODES:
        return {"ok": False, "error": f"Unknown capture mode '{mode}'. Use suricata or tcpdump."}

    iface = (interface or "").strip() or str(config.get("CAPTURE_INTERFACE") or "").strip()
    if not iface:
        return {"ok": False, "error": "No capture interface. Pick one or set CAPTURE_INTERFACE in .env."}

    current = capture_status(config)
    if current.get("running"):
        return {
            "ok": False,
            "error": f"Capture already running ({current.get('mode')} on {current.get('interface')}). Stop it first.",
        }

    if mode == "suricata":
        result = suricata_manager.start_suricata(config, interface=iface)
        if not result.get("ok"):
            return result
        pid = result.get("pid")
        command = result.get("command")
        eve_hint = result.get("eve_hint")
        effective_chunk_dir = None
    else:
        result = _start_tcpdump(config, iface)
        if not result.get("ok"):
            return result
        pid = result.get("pid")
        command = result.get("command")
        eve_hint = None
        effective_chunk_dir = result.get("chunk_dir")

    state = {
        "mode": mode,
        "pid": pid,
        "interface": iface,
        "command": command,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    if mode == "tcpdump" and effective_chunk_dir:
        state["chunk_dir"] = effective_chunk_dir
    _write_state(config, state)
    logger.info("Capture started: mode=%s iface=%s pid=%s", mode, iface, pid)
    out = {"ok": True, "mode": mode, "pid": pid, "interface": iface, "eve_hint": eve_hint, "command": command}
    return out


def _start_tcpdump(config: dict, iface: str) -> dict:
    binary = _resolve_tcpdump(config)
    if not binary:
        return {
            "ok": False,
            "error": "tcpdump not found. Install it (apt install tcpdump) or set TCPDUMP_BIN in .env.",
        }

    if sys.platform != "win32" and not running_as_root():
        from app.services.capture.privileges import passwordless_sudo_available

        if not passwordless_sudo_available():
            return {
                "ok": False,
                "error": "Live tcpdump capture requires root on Linux.",
                "hint": "cd ~/packetEye && sudo python run.py",
            }

    seconds = max(30, int(config.get("TCPDUMP_CHUNK_SECONDS", 300)))
    chunk_pattern = f"chunk_{os.getpid()}_%Y%m%d_%H%M%S.pcap"
    tcpdump_args = [
        "-i", iface,
        "-s", "0",
        "-n",
        "-U",
        "-w", "",  # filled per attempt
        "-G", str(seconds),
    ]

    last_error: dict = {"ok": False, "error": "tcpdump failed to start."}
    for chunk_dir in chunk_dir_candidates(config):
        ok, err, reclaimed = prepare_tcpdump_chunk_dir(chunk_dir)
        if not ok:
            last_error = {"ok": False, "error": err, "hint": live_capture_privilege_hint()}
            continue

        args = list(tcpdump_args)
        args[args.index("-w") + 1] = str(chunk_dir / chunk_pattern)
        cmd, sudo_err = build_tcpdump_command(config, binary, args)
        if sudo_err:
            return {"ok": False, "error": sudo_err, "hint": "Run: sudo python run.py"}

        startup_log = chunk_dir / "tcpdump-start.log"
        try:
            with open(startup_log, "wb") as log_f:
                proc = subprocess.Popen(cmd, stdout=log_f, stderr=subprocess.STDOUT)
        except OSError as exc:
            last_error = {"ok": False, "error": f"Failed to start tcpdump: {exc}"}
            continue

        time.sleep(1.0)
        if proc.poll() is not None:
            detail = ""
            try:
                detail = startup_log.read_text(encoding="utf-8", errors="replace").strip()[-2000:]
            except OSError:
                pass
            err = (
                f"tcpdump exited immediately (code {proc.returncode}). "
                f"Chunk dir: {chunk_dir}"
            )
            if detail:
                err += f"\n\n{detail}"
            hint = tcpdump_failure_hint(detail, chunk_dir)
            if iface == "lo":
                hint = (hint or "") + "\n\nTip: avoid loopback (lo) — use eth0 or wlan0."
            last_error = {"ok": False, "error": err, "hint": (hint or "").strip(), "chunk_dir": str(chunk_dir)}
            if reclaimed:
                last_error["reclaimed_chunks"] = reclaimed
            if "permission denied" in detail.lower() and ".pcap" in detail.lower():
                logger.warning("tcpdump PCAP write failed in %s, trying next chunk dir", chunk_dir)
                continue
            return last_error

        _tcpdump["process"] = proc
        return {
            "ok": True,
            "pid": proc.pid,
            "command": " ".join(cmd),
            "chunk_dir": str(chunk_dir),
            "reclaimed_chunks": reclaimed,
        }

    return last_error


def stop_capture(config: dict) -> dict:
    state = _read_state(config)
    mode = state.get("mode")
    suricata = suricata_manager.get_status(config)
    managed = bool(suricata.get("managed"))

    if managed:
        result = suricata_manager.stop_suricata()
        if result.get("ok"):
            _clear_state(config)
            logger.info("Capture stopped (suricata)")
        return result

    proc = _tcpdump.get("process")
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        except OSError as exc:
            return {"ok": False, "error": f"Failed to stop tcpdump: {exc}"}
        _tcpdump["process"] = None
        _clear_state(config)
        logger.info("Capture stopped (tcpdump)")
        return {"ok": True}

    pid = state.get("pid")
    if mode == "tcpdump" and _pid_alive(pid):
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/F"],
                    capture_output=True,
                    timeout=15,
                )
            else:
                os.kill(pid, 15)
        except OSError as exc:
            return {"ok": False, "error": f"Failed to signal tcpdump pid {pid}: {exc}"}
        _clear_state(config)
        logger.info("Capture stopped (tcpdump pid %s via state file)", pid)
        return {"ok": True}

    had_stale_state = bool(state)
    if had_stale_state:
        _clear_state(config)

    if suricata.get("running") and not managed:
        return {
            "ok": False,
            "error": (
                "Suricata is running on this host but was not started by packetEye. "
                "Stop it from Windows Services / Task Manager, or use the Suricata Management panel."
            ),
            "cleared_stale_state": had_stale_state,
        }

    return {
        "ok": False,
        "error": "No capture process is running.",
        "cleared_stale_state": had_stale_state,
    }


def capture_status(config: dict) -> dict:
    state = _read_state(config)
    suricata = suricata_manager.get_status(config)
    tcpdump_proc = _tcpdump.get("process")
    tcpdump_running = (
        (tcpdump_proc is not None and tcpdump_proc.poll() is None)
        or (state.get("mode") == "tcpdump" and _pid_alive(state.get("pid")))
    )
    state = _clear_stale_state(config, state, suricata, tcpdump_running)

    managed = bool(suricata.get("managed"))
    external_suricata = bool(suricata.get("running") and not managed)

    if managed:
        running, active_mode, stoppable = True, "suricata", True
    elif tcpdump_running:
        running, active_mode, stoppable = True, "tcpdump", True
    else:
        running, active_mode, stoppable = False, None, False

    pid = None
    if managed:
        pid = suricata.get("managed_pid") or state.get("pid")
    elif tcpdump_running:
        pid = (tcpdump_proc.pid if tcpdump_proc and tcpdump_proc.poll() is None else None) or state.get("pid")

    return {
        "running": running,
        "stoppable": stoppable,
        "external_suricata": external_suricata,
        "mode": active_mode,
        "configured_mode": str(config.get("CAPTURE_MODE") or "suricata"),
        "interface": state.get("interface") or str(config.get("CAPTURE_INTERFACE") or ""),
        "pid": pid,
        "started_at": state.get("started_at"),
        "command": state.get("command"),
        "suricata": {
            "installed": suricata.get("installed"),
            "running": suricata.get("running"),
            "managed": managed,
            "version": suricata.get("version"),
            "eve": suricata.get("eve"),
        },
        "tcpdump": {
            "installed": _resolve_tcpdump(config) is not None,
            "running": tcpdump_running,
            "chunks": _chunk_stats(config),
        },
        "platform": sys.platform,
    }
