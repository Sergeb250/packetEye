"""Manage the Suricata process, EVE output, and custom rules from the dashboard."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from app.services.capture.privileges import ensure_writable_dir, live_capture_privilege_hint, running_as_root

logger = logging.getLogger(__name__)

# Process handle for a Suricata instance started from the dashboard. Instances
# started outside packetEye are detected (status) but not stopped from here.
_managed: dict = {"process": None, "started_at": None, "command": None}

MAX_RULES_BYTES = 512 * 1024
_version_cache: dict[str, str | None] = {}
_STARTUP_LOG = "suricata-start.log"


def _project_root(config: dict) -> Path:
    for candidate in (
        Path(str(config.get("SURICATA_CUSTOM_RULES_PATH") or "")).resolve().parent.parent.parent,
        Path(str(config.get("SURICATA_LOG_DIR") or "")).resolve().parent.parent,
        Path.cwd(),
    ):
        if (candidate / "app").is_dir():
            return candidate
    return Path.cwd()


_last_diagnostics: list[dict] = []
_eve_monitor_offset: dict[str, int] = {}
_discovered_eve: dict = {"path": None, "source": None, "checked_at": 0.0}

_RUNTIME_YAML = """%YAML 1.1
---
default-log-dir: .

vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: "1521"
    SSH_PORTS: "22"
    DNP3_PORTS: "20000"
    FTP_PORTS: "21"
    GENEVE_PORTS: "6081"
    VXLAN_PORTS: "4789"
    TEREDO_PORTS: "3544"

sensor-name: packeteye

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - flow
        - alert
        - dns
        - http
        - tls
        - anomaly

logging:
  default-log-level: notice

af-packet:
  - interface: {iface}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

detect:
  profile: medium

default-rule-path: {rule_path}
rule-files:
{rule_files}
{run_as}
"""


def parse_suricata_output(text: str) -> list[dict]:
    """Parse Suricata stderr/stdout into tabular diagnostic rows."""
    rows: list[dict] = []
    for i, raw in enumerate(text.splitlines()):
        line = raw.strip()
        if not line:
            continue
        lower = line.lower()
        severity = "info"
        if any(x in lower for x in ("fatal", "failed", "error:", "[error")):
            severity = "critical"
        elif "error" in lower or " err " in lower:
            severity = "error"
        elif "warning" in lower or "warn" in lower:
            severity = "warning"
        category = "general"
        if "rule" in lower:
            category = "rules"
        elif "yaml" in lower or "config" in lower:
            category = "config"
        elif any(x in lower for x in ("pcap", "af-packet", "interface", "live device")):
            category = "capture"
        elif "permission" in lower or "cap_" in lower:
            category = "permissions"
        rows.append(
            {
                "line": i + 1,
                "severity": severity,
                "category": category,
                "message": line[:500],
            }
        )
    return rows


def _build_runtime_config(config: dict, interface: str) -> tuple[str, str]:
    """Write a minimal Suricata yaml when no system/bundled config is available."""
    log_dir = Path(str(config.get("SURICATA_LOG_DIR") or "data/suricata"))
    log_dir.mkdir(parents=True, exist_ok=True)
    runtime = log_dir / "packeteye-runtime.yaml"

    system_rules_file = Path("/etc/suricata/rules/suricata.rules")
    if system_rules_file.is_file():
        rule_path = "/etc/suricata/rules"
        rule_files = "  - suricata.rules"
    else:
        rule_path = str(Path(str(config.get("SURICATA_CUSTOM_RULES_PATH") or "deploy/suricata")).parent)
        rule_files = ""

    run_as = ""
    if running_as_root():
        run_as = "run-as:\n  user: root\n  group: root"

    runtime.write_text(
        _RUNTIME_YAML.format(
            iface=interface,
            rule_path=rule_path,
            rule_files=rule_files,
            run_as=run_as,
        ),
        encoding="utf-8",
    )
    return str(runtime), "runtime"


def _resolve_run_config(config: dict, interface: str) -> tuple[str, str]:
    """Prefer system (/etc) or bundled suricata.yaml; runtime yaml is last resort."""
    base_path, base_src = _resolve_config_path(config)
    if base_path and base_src != "missing":
        return base_path, base_src
    return _build_runtime_config(config, interface)


def _build_suricata_args(config: dict, iface: str) -> tuple[list[str], str, str, str | None]:
    """Assemble suricata CLI args (-c, -i, -l, optional -S) after path/privilege checks."""
    log_dir = Path(str(config.get("SURICATA_LOG_DIR") or "data/suricata")).resolve()
    ok, err = ensure_writable_dir(log_dir)
    if not ok:
        return [], "", "missing", err

    config_path, cfg_source = _resolve_run_config(config, iface)
    sur_args = ["-c", config_path, "-i", iface, "-l", str(log_dir)]

    rules_path = Path(str(config.get("SURICATA_CUSTOM_RULES_PATH") or ""))
    if rules_path.is_file() and rules_path.stat().st_size > 0:
        sur_args += ["-S", str(rules_path.resolve())]

    priv = live_capture_privilege_hint()
    if priv and cfg_source == "runtime":
        # Non-root + fallback runtime config often fails eve-log setup after cap drop.
        return sur_args, config_path, cfg_source, priv

    return sur_args, config_path, cfg_source, None


def get_diagnostics(config: dict) -> dict:
    log_dir = Path(str(config.get("SURICATA_LOG_DIR") or "data/suricata"))
    startup = _read_log_tail(log_dir / _STARTUP_LOG, 8000)
    rows = list(_last_diagnostics)
    if startup:
        rows.extend(parse_suricata_output(startup))
    base_path, base_src = _resolve_config_path(config)
    return {
        "rows": rows[-120:],
        "startup_log": startup,
        "last_command": _managed.get("command"),
        "base_config": base_path,
        "base_config_source": base_src,
    }


def poll_monitor_events(config: dict, since_id: int = 0) -> list[dict]:
    """Tail EVE and return tabular monitor rows for the Suricata dashboard."""
    import json

    from app.services.live.eve_parser import normalize_eve_event
    from app.services.live.packet_feed import eve_event_to_row

    eve_path = _resolve_eve_path(config)
    if not eve_path.is_file():
        return []

    key = str(eve_path)
    offset = _eve_monitor_offset.get(key, 0)
    rows: list[dict] = []
    seq = since_id

    with open(eve_path, encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        for _ in range(80):
            line = f.readline()
            if not line:
                break
            offset = f.tell()
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = normalize_eve_event(json.loads(line))
            except json.JSONDecodeError:
                continue
            if not event:
                continue
            row = eve_event_to_row(event)
            if row:
                seq += 1
                row["id"] = seq
                rows.append(row)
    _eve_monitor_offset[key] = offset
    if since_id <= 0:
        return rows[-200:]
    return [r for r in rows if r["id"] > since_id]


def run_preflight(config: dict, interface: str) -> dict:
    """Run suricata -T and return parsed tabular diagnostics without starting."""
    binary = _resolve_binary(config)
    if not binary:
        return {"ok": False, "error": "Suricata not installed", "diagnostics": []}

    iface = (interface or "").strip() or str(config.get("SURICATA_INTERFACE") or "").strip()
    if not iface:
        return {"ok": False, "error": "No interface selected", "diagnostics": []}
    if iface == "lo" and not config.get("SURICATA_ALLOW_LOOPBACK"):
        return {
            "ok": False,
            "error": "Interface lo is blocked",
            "hint": "Select eth0/wlan0. Set SURICATA_ALLOW_LOOPBACK=true to allow loopback.",
            "diagnostics": parse_suricata_output("Error: loopback interface lo is not allowed"),
        }

    log_dir = Path(str(config.get("SURICATA_LOG_DIR") or "data/suricata"))
    log_dir.mkdir(parents=True, exist_ok=True)
    sur_args, config_path, cfg_source, prep_err = _build_suricata_args(config, iface)
    if prep_err:
        diag = parse_suricata_output(f"Error: {prep_err}")
        _last_diagnostics.clear()
        _last_diagnostics.extend(diag)
        return {
            "ok": False,
            "error": prep_err,
            "hint": "On Kali run: sudo python run.py",
            "diagnostics": diag,
        }

    ok, detail = _suricata_test(binary, sur_args)
    diag = parse_suricata_output(detail)
    cmd = f"{binary} -T {' '.join(sur_args)}"
    return {
        "ok": ok,
        "command": cmd,
        "config_path": config_path,
        "config_source": cfg_source,
        "interface": iface,
        "diagnostics": diag,
        "error": None if ok else f"Preflight failed ({cfg_source} config)",
        "hint": _permission_hint(detail),
    }


def _resolve_config_path(config: dict) -> tuple[str | None, str]:
    explicit = str(config.get("SURICATA_CONFIG_PATH") or "").strip()
    if explicit and Path(explicit).is_file():
        return explicit, "env"
    system = Path("/etc/suricata/suricata.yaml")
    if system.is_file():
        return str(system), "system"
    bundled = _project_root(config) / "deploy" / "suricata" / "suricata.yaml"
    if bundled.is_file():
        return str(bundled), "bundled"
    return None, "missing"


def _read_log_tail(path: Path, max_chars: int = 2500) -> str:
    if not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return text.strip()[-max_chars:]
    except OSError:
        return ""


def _permission_hint(detail: str) -> str | None:
    lower = detail.lower()
    if "eve-log" in lower and "setup failed" in lower:
        return (
            "eve-log could not open its output file — usually a permissions issue. "
            "Run packetEye as root (sudo python run.py) and ensure SURICATA_LOG_DIR is writable."
        )
    if any(x in lower for x in ("permission denied", "operation not permitted", "cap_net", "cannot open", "not writable")):
        return (
            "Capture needs elevated privileges. Run packetEye as root: sudo python run.py — "
            "or grant capabilities: sudo setcap cap_net_raw,cap_net_admin=eip $(which suricata)"
        )
    if "lo" in lower and "pcap" in lower:
        return "Avoid loopback (lo) unless testing locally — pick eth0, wlan0, or your active interface."
    return None


def _suricata_test(binary: str, args: list[str]) -> tuple[bool, str]:
    test_cmd = [binary, "-T", *args]
    try:
        out = subprocess.run(test_cmd, capture_output=True, text=True, timeout=90)
        detail = (out.stderr or out.stdout or "").strip()
        return out.returncode == 0, detail[-2500:]
    except subprocess.TimeoutExpired:
        return False, "Suricata config test timed out after 90s."
    except OSError as exc:
        return False, str(exc)


def _resolve_binary(config: dict) -> str | None:
    binary = str(config.get("SURICATA_BIN") or "suricata")
    found = shutil.which(binary)
    if found:
        return found
    return binary if Path(binary).is_file() else None


def get_version(config: dict) -> str | None:
    binary = _resolve_binary(config)
    if not binary:
        return None
    if binary in _version_cache:
        return _version_cache[binary]
    version = None
    try:
        out = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=10)
        text = (out.stdout or out.stderr or "").strip()
        if text:
            version = text.splitlines()[0].strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("suricata -V failed: %s", exc)
    _version_cache[binary] = version
    return version


def _find_running_pids() -> list[int]:
    """PIDs of any suricata processes on the host (managed or external)."""
    try:
        import psutil

        return [
            p.pid
            for p in psutil.process_iter(["name"])
            if "suricata" in ((p.info.get("name") or "").lower())
        ]
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("psutil scan failed: %s", exc)

    try:
        if sys.platform == "win32":
            out = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq suricata.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            pids = []
            for line in out.stdout.splitlines():
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) >= 2 and "suricata" in parts[0].lower():
                    try:
                        pids.append(int(parts[1]))
                    except ValueError:
                        continue
            return pids
        out = subprocess.run(["pgrep", "-x", "suricata"], capture_output=True, text=True, timeout=10)
        return [int(p) for p in out.stdout.split() if p.isdigit()]
    except (OSError, subprocess.TimeoutExpired):
        return []


def _managed_process_alive() -> bool:
    proc = _managed.get("process")
    return proc is not None and proc.poll() is None


def _parse_eve_from_yaml(config_path: Path) -> Path | None:
    """Best-effort EVE path from suricata.yaml without PyYAML."""
    import re

    if not config_path.is_file():
        return None
    try:
        text = config_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    log_dir = "."
    m = re.search(r"default-log-dir:\s*(\S+)", text)
    if m:
        log_dir = m.group(1).strip("\"'")
    eve_name = "eve.json"
    for block in re.finditer(r"eve-log:[\s\S]*?(?=\n\s*\w|\Z)", text):
        fm = re.search(r"filename:\s*(\S+)", block.group(0))
        if fm:
            eve_name = fm.group(1).strip("\"'")
            break
    base = config_path.parent
    log_path = Path(log_dir)
    if log_path.is_absolute():
        return log_path / eve_name
    if log_dir == ".":
        return base / eve_name
    return base / log_dir / eve_name


def discover_eve_path(config: dict) -> tuple[Path, str]:
    """Resolve EVE file path and how it was discovered."""
    if _managed_process_alive():
        log_dir = Path(str(config.get("SURICATA_LOG_DIR") or ""))
        if log_dir.is_dir():
            return log_dir / "eve.json", "managed"

    configured = str(config.get("SURICATA_EVE_PATH") or "").strip()
    if configured:
        p = Path(configured)
        if p.is_file():
            return p, "config"

    log_dir = Path(str(config.get("SURICATA_LOG_DIR") or ""))
    if log_dir.is_dir():
        candidate = log_dir / "eve.json"
        if candidate.is_file():
            return candidate, "log_dir"

    cfg_path, _ = _resolve_config_path(config)
    if cfg_path:
        from_yaml = _parse_eve_from_yaml(Path(cfg_path))
        if from_yaml and from_yaml.is_file():
            return from_yaml, "yaml"

    if configured:
        return Path(configured), "config"
    if log_dir.is_dir():
        return log_dir / "eve.json", "log_dir"
    return Path(), "unknown"


def _resolve_eve_path(config: dict) -> Path:
    path, source = discover_eve_path(config)
    _discovered_eve.update({"path": str(path) if str(path) else None, "source": source, "checked_at": time.time()})
    return path


def _eve_stats(config: dict) -> dict:
    eve_path = _resolve_eve_path(config)
    stats = {
        "path": str(eve_path) if str(eve_path) != "." else "",
        "exists": eve_path.is_file(),
        "size_bytes": 0,
        "age_seconds": None,
        "events_per_second": None,
        "source": _discovered_eve.get("source") or "unknown",
        "discovered": bool(_discovered_eve.get("path")),
    }
    if not stats["exists"]:
        return stats

    st = eve_path.stat()
    stats["size_bytes"] = st.st_size
    stats["age_seconds"] = round(max(0.0, time.time() - st.st_mtime), 1)

    # Estimate throughput from the timestamps in the newest chunk of the log.
    try:
        with open(eve_path, "rb") as f:
            f.seek(max(0, st.st_size - 65536))
            lines = f.read().decode("utf-8", errors="replace").splitlines()
        import json as _json

        timestamps = []
        for line in lines[-200:]:
            line = line.strip().rstrip(",")
            if not line.startswith("{"):
                continue
            try:
                ts = _json.loads(line).get("timestamp")
            except _json.JSONDecodeError:
                continue
            if ts:
                try:
                    timestamps.append(
                        datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
                    )
                except ValueError:
                    continue
        if len(timestamps) >= 2:
            span = max(timestamps) - min(timestamps)
            if span > 0:
                stats["events_per_second"] = round(len(timestamps) / span, 2)
    except OSError:
        pass
    return stats


def get_status(config: dict) -> dict:
    binary = _resolve_binary(config)
    pids = _find_running_pids()
    managed_alive = _managed_process_alive()
    rules_path = Path(str(config.get("SURICATA_CUSTOM_RULES_PATH") or ""))
    cfg_path, cfg_source = _resolve_config_path(config)

    return {
        "installed": binary is not None,
        "binary": binary,
        "version": get_version(config),
        "running": managed_alive or bool(pids),
        "pids": pids,
        "managed": managed_alive,
        "managed_pid": _managed["process"].pid if managed_alive else None,
        "managed_started_at": _managed.get("started_at") if managed_alive else None,
        "managed_command": _managed.get("command") if managed_alive else None,
        "config_path": cfg_path or "",
        "config_source": cfg_source,
        "interface": str(config.get("SURICATA_INTERFACE") or ""),
        "log_dir": str(config.get("SURICATA_LOG_DIR") or ""),
        "eve": _eve_stats(config),
        "custom_rules": {
            "path": str(rules_path) if str(rules_path) != "." else "",
            "exists": rules_path.is_file(),
            "size_bytes": rules_path.stat().st_size if rules_path.is_file() else 0,
        },
        "platform": sys.platform,
    }


def list_interfaces() -> list[dict]:
    try:
        import socket

        import psutil

        interfaces = []
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            ips = [a.address for a in addrs if a.family == socket.AF_INET]
            interfaces.append(
                {
                    "name": name,
                    "up": bool(stats.get(name).isup) if name in stats else None,
                    "addresses": ips[:3],
                    "loopback": name in ("lo", "Loopback Pseudo-Interface 1"),
                }
            )
        interfaces.sort(
            key=lambda i: (
                i.get("loopback", False),
                i.get("up") is False,
                0 if i["name"].startswith(("eth", "enp", "ens", "wlan", "wlp")) else 1,
                i["name"],
            )
        )
        return interfaces
    except ImportError:
        logger.info("psutil not installed; cannot enumerate interfaces")
        return []
    except Exception as exc:
        logger.warning("Interface enumeration failed: %s", exc)
        return []


def start_suricata(config: dict, interface: str | None = None) -> dict:
    if _managed_process_alive():
        return {"ok": False, "error": "Suricata already running (managed by packetEye)."}
    if _find_running_pids():
        return {"ok": False, "error": "A Suricata process is already running on this host."}

    binary = _resolve_binary(config)
    if not binary:
        return {
            "ok": False,
            "error": "Suricata binary not found. Install Suricata and/or set SURICATA_BIN in .env.",
        }

    iface = (interface or "").strip() or str(config.get("SURICATA_INTERFACE") or "").strip()
    if not iface:
        return {"ok": False, "error": "No capture interface configured. Pick one or set SURICATA_INTERFACE."}
    if iface == "lo" and not config.get("SURICATA_ALLOW_LOOPBACK"):
        diag = parse_suricata_output("Error: loopback interface lo blocked — use eth0, wlan0, or enp*")
        _last_diagnostics.clear()
        _last_diagnostics.extend(diag)
        return {
            "ok": False,
            "error": "Interface 'lo' (loopback) is not allowed. Select eth0, wlan0, or your active NIC.",
            "hint": "Loopback only captures local traffic. Set SURICATA_ALLOW_LOOPBACK=true in .env to override.",
            "diagnostics": diag,
        }

    sur_args, config_path, cfg_source, prep_err = _build_suricata_args(config, iface)
    if prep_err:
        return {
            "ok": False,
            "error": prep_err,
            "hint": "On Kali run: sudo python run.py",
            "diagnostics": parse_suricata_output(f"Error: {prep_err}"),
        }

    log_dir = Path(str(config.get("SURICATA_LOG_DIR") or "data/suricata"))
    startup_log = log_dir / _STARTUP_LOG

    ok, test_detail = _suricata_test(binary, sur_args)
    diag = parse_suricata_output(test_detail)
    _last_diagnostics.clear()
    _last_diagnostics.extend(diag)
    if not ok:
        hint = _permission_hint(test_detail)
        cmd = f"{binary} -T {' '.join(sur_args)}"
        err = f"Suricata preflight failed ({cfg_source} config at {config_path})."
        if test_detail:
            err += f"\n\n{test_detail[-1500:]}"
        return {
            "ok": False,
            "error": err,
            "hint": hint,
            "config_path": config_path,
            "command": cmd,
            "diagnostics": diag,
        }

    cmd = [binary, *sur_args]
    try:
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        with open(startup_log, "wb") as log_f:
            proc = subprocess.Popen(
                cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
    except OSError as exc:
        return {"ok": False, "error": f"Failed to start Suricata: {exc}"}

    time.sleep(1.5)
    if proc.poll() is not None:
        detail = _read_log_tail(startup_log)
        diag = parse_suricata_output(detail)
        _last_diagnostics.clear()
        _last_diagnostics.extend(diag)
        hint = _permission_hint(detail)
        err = (
            f"Suricata exited immediately (code {proc.returncode}). "
            f"Command: {' '.join(cmd)}"
        )
        if detail:
            err += f"\n\n{detail[-1500:]}"
        return {
            "ok": False,
            "error": err,
            "hint": hint,
            "config_path": config_path,
            "command": " ".join(cmd),
            "diagnostics": diag,
        }

    _managed["process"] = proc
    _managed["started_at"] = datetime.now(timezone.utc).isoformat()
    _managed["command"] = " ".join(cmd)
    logger.info("Started Suricata (pid %s): %s", proc.pid, _managed["command"])
    return {
        "ok": True,
        "pid": proc.pid,
        "command": _managed["command"],
        "eve_hint": str(log_dir / "eve.json"),
        "config_path": config_path,
        "config_source": cfg_source,
    }


def stop_suricata() -> dict:
    proc = _managed.get("process")
    if not _managed_process_alive():
        _managed["process"] = None
        if _find_running_pids():
            return {
                "ok": False,
                "error": "Running Suricata was not started by packetEye — stop it from the host.",
            }
        return {"ok": False, "error": "Suricata is not running."}

    try:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    except OSError as exc:
        return {"ok": False, "error": f"Failed to stop Suricata: {exc}"}

    _managed["process"] = None
    _managed["started_at"] = None
    _managed["command"] = None
    logger.info("Stopped managed Suricata process")
    return {"ok": True}


def test_rules_draft(config: dict, content: str, interface: str = "") -> dict:
    """Validate draft rule text with suricata -T without saving to custom.rules."""
    draft = (content or "").strip()
    if not draft:
        return {"ok": False, "error": "No rules content provided."}
    binary = _resolve_binary(config)
    if not binary:
        return {"ok": False, "error": "Suricata not installed"}

    iface = (interface or "").strip() or str(config.get("SURICATA_INTERFACE") or "").strip()
    if not iface:
        return {"ok": False, "error": "No interface selected"}

    log_dir = Path(str(config.get("SURICATA_LOG_DIR") or "data/suricata"))
    log_dir.mkdir(parents=True, exist_ok=True)
    draft_path = log_dir / "_draft_rules_test.rules"
    try:
        draft_path.write_text(draft, encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "error": f"Could not write draft rules: {exc}"}

    cfg = dict(config)
    cfg["SURICATA_CUSTOM_RULES_PATH"] = str(draft_path)
    sur_args, config_path, cfg_source, prep_err = _build_suricata_args(cfg, iface)
    if prep_err:
        return {"ok": False, "error": prep_err, "diagnostics": parse_suricata_output(f"Error: {prep_err}")}

    ok, detail = _suricata_test(binary, sur_args)
    return {
        "ok": ok,
        "config_path": config_path,
        "config_source": cfg_source,
        "diagnostics": parse_suricata_output(detail),
        "error": None if ok else "Rule validation failed",
    }


def read_rules(config: dict) -> dict:
    rules_path = Path(str(config.get("SURICATA_CUSTOM_RULES_PATH") or ""))
    if not str(config.get("SURICATA_CUSTOM_RULES_PATH") or "").strip():
        return {"ok": False, "error": "SURICATA_CUSTOM_RULES_PATH not configured."}
    if not rules_path.is_file():
        return {"ok": True, "path": str(rules_path), "content": "", "exists": False}
    try:
        content = rules_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"ok": False, "error": f"Could not read rules: {exc}"}
    return {"ok": True, "path": str(rules_path), "content": content, "exists": True}


def write_rules(config: dict, content: str) -> dict:
    rules_path = Path(str(config.get("SURICATA_CUSTOM_RULES_PATH") or ""))
    if not str(config.get("SURICATA_CUSTOM_RULES_PATH") or "").strip():
        return {"ok": False, "error": "SURICATA_CUSTOM_RULES_PATH not configured."}
    if content is None:
        return {"ok": False, "error": "No rules content provided."}
    raw = content.encode("utf-8")
    if len(raw) > MAX_RULES_BYTES:
        return {"ok": False, "error": f"Rules file too large (max {MAX_RULES_BYTES // 1024} KB)."}
    if b"\x00" in raw:
        return {"ok": False, "error": "Rules content contains binary data."}

    try:
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        rules_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "error": f"Could not write rules: {exc}"}

    reloaded = _reload_rules()
    return {
        "ok": True,
        "path": str(rules_path),
        "size_bytes": len(raw),
        "reloaded": reloaded,
        "hint": None if reloaded else "Restart Suricata to apply the updated rules.",
    }


def _reload_rules() -> bool:
    """Ask a managed Suricata to hot-reload rules (POSIX only, via SIGUSR2)."""
    if not _managed_process_alive() or sys.platform == "win32":
        return False
    try:
        import signal

        os.kill(_managed["process"].pid, signal.SIGUSR2)
        return True
    except (OSError, AttributeError):
        return False
