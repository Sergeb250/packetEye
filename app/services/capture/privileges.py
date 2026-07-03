"""Privilege and filesystem checks for live capture (Suricata / tcpdump)."""

from __future__ import annotations

import logging
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# tcpdump on Kali/Ubuntu is often AppArmor-confined and cannot write PCAPs under $HOME.
_LINUX_ROOT_CHUNKS = Path("/var/log/packeteye/chunks")


def running_as_root() -> bool:
    if sys.platform == "win32":
        return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def default_tcpdump_chunk_dir(base_dir: Path | None = None) -> Path:
    """Platform default — avoids AppArmor blocking writes to ~/packetEye/data/..."""
    if sys.platform == "win32":
        root = base_dir or Path.cwd()
        return (root / "data" / "capture" / "chunks").resolve()
    if running_as_root():
        return _LINUX_ROOT_CHUNKS
    try:
        uid = os.getuid()
    except AttributeError:
        uid = 0
    return Path(f"/tmp/packeteye/chunks-{uid}")


def resolve_tcpdump_chunk_dir(config: dict) -> Path:
    explicit = str(config.get("TCPDUMP_CHUNK_DIR") or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    base = Path(str(config.get("BASE_DIR") or Path.cwd()))
    return default_tcpdump_chunk_dir(base)


def _sudo_owner() -> tuple[int, int] | None:
    if not running_as_root():
        return None
    sudo_uid = os.environ.get("SUDO_UID", "")
    sudo_gid = os.environ.get("SUDO_GID", "")
    if sudo_uid.isdigit() and sudo_gid.isdigit() and int(sudo_uid) > 0:
        return int(sudo_uid), int(sudo_gid)
    return None


def _ownership_fix_hint(path: Path) -> str:
    return f"sudo chown -R $USER:$USER {path}"


def ensure_writable_dir(path: Path) -> tuple[bool, str | None]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".packeteye_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True, None
    except OSError as exc:
        return False, (
            f"Directory not writable: {path} ({exc}). "
            f"Fix: {_ownership_fix_hint(path)} — or run: sudo python run.py"
        )


def _apply_dir_owner(path: Path, uid: int, gid: int) -> None:
    try:
        os.chown(path, uid, gid)
        os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    except OSError as exc:
        logger.debug("Could not chown %s: %s", path, exc)


def _unwritable_chunk_files(chunk_dir: Path) -> list[Path]:
    if not chunk_dir.is_dir():
        return []
    return [
        p
        for p in chunk_dir.glob("chunk_*.pcap")
        if p.is_file() and not os.access(p, os.W_OK)
    ]


def reclaim_unwritable_chunks(chunk_dir: Path) -> list[str]:
    removed: list[str] = []
    for path in _unwritable_chunk_files(chunk_dir):
        try:
            path.unlink()
            removed.append(path.name)
            logger.info("Removed unwritable chunk file: %s", path.name)
        except OSError as exc:
            logger.warning("Could not remove unwritable chunk %s: %s", path, exc)
    return removed


def prepare_tcpdump_chunk_dir(chunk_dir: Path) -> tuple[bool, str | None, list[str]]:
    chunk_dir.mkdir(parents=True, exist_ok=True)

    owner = _sudo_owner()
    if owner:
        _apply_dir_owner(chunk_dir, owner[0], owner[1])

    removed = reclaim_unwritable_chunks(chunk_dir)

    blocking = _unwritable_chunk_files(chunk_dir)
    if blocking:
        names = ", ".join(p.name for p in blocking[:5])
        return (
            False,
            (
                f"PCAP chunk directory has files owned by another user ({names}). "
                f"Fix: sudo rm {chunk_dir}/chunk_*.pcap && {_ownership_fix_hint(chunk_dir)}"
            ),
            removed,
        )

    ok, err = ensure_writable_dir(chunk_dir)
    return ok, err, removed


def passwordless_sudo_available() -> bool:
    sudo = shutil.which("sudo")
    if not sudo:
        return False
    try:
        proc = subprocess.run([sudo, "-n", "true"], capture_output=True, timeout=5)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def build_tcpdump_command(config: dict, binary: str, tcpdump_args: list[str]) -> tuple[list[str] | None, str | None]:
    """
    Build tcpdump argv. On Linux when not root, wrap with `sudo -n` so capture + PCAP
    write work under AppArmor (tcpdump often cannot write to $HOME).
    """
    if running_as_root() or sys.platform == "win32":
        return [binary, *tcpdump_args], None

    use_sudo = config.get("CAPTURE_USE_SUDO", True)
    if not use_sudo:
        return [binary, *tcpdump_args], None

    sudo = shutil.which("sudo")
    if not sudo:
        return None, "sudo not found. Run packetEye as root: sudo python run.py"

    if not passwordless_sudo_available():
        return None, (
            "tcpdump needs root on Linux. Either run packetEye as root:\n"
            "  sudo python run.py\n"
            "Or allow passwordless sudo for tcpdump:\n"
            "  sudo visudo  # add: kali ALL=(ALL) NOPASSWD: /usr/bin/tcpdump"
        )

    return [sudo, "-n", binary, *tcpdump_args], None


def chunk_dir_candidates(config: dict) -> list[Path]:
    """Ordered chunk directories to try — Linux-safe paths first (AppArmor)."""
    primary = resolve_tcpdump_chunk_dir(config)
    fallback = default_tcpdump_chunk_dir(Path(str(config.get("BASE_DIR") or Path.cwd())))
    if sys.platform != "win32":
        ordered = [fallback, _LINUX_ROOT_CHUNKS, primary]
    else:
        ordered = [primary, fallback]
    out: list[Path] = []
    for path in ordered:
        if path not in out:
            out.append(path)
    return out


def ensure_capture_paths(config: dict) -> dict[str, str | None]:
    paths = {
        "capture_state": Path(str(config.get("CAPTURE_STATE_DIR") or "data/capture")),
        "tcpdump_chunks": resolve_tcpdump_chunk_dir(config),
        "suricata_logs": Path(str(config.get("SURICATA_LOG_DIR") or "data/suricata")),
    }
    errors: dict[str, str | None] = {}
    owner = _sudo_owner()

    for key, path in paths.items():
        try:
            path.mkdir(parents=True, exist_ok=True)
            if owner:
                _apply_dir_owner(path, owner[0], owner[1])
            if key == "tcpdump_chunks":
                ok, err, _ = prepare_tcpdump_chunk_dir(path)
            else:
                ok, err = ensure_writable_dir(path)
            errors[key] = None if ok else err
        except OSError as exc:
            errors[key] = str(exc)

    return errors


def live_capture_privilege_hint() -> str | None:
    if sys.platform == "win32":
        return None
    if running_as_root():
        return None
    if passwordless_sudo_available():
        return None
    return "Live capture needs root on Linux. Restart with: sudo python run.py"


def tcpdump_failure_hint(detail: str, chunk_dir: Path) -> str | None:
    lower = detail.lower()
    if "permission denied" in lower and ".pcap" in lower:
        fallback = default_tcpdump_chunk_dir()
        return (
            "tcpdump cannot write PCAP files to this path (common on Kali: AppArmor blocks "
            f"writes under $HOME). Set in .env:\n"
            f"  TCPDUMP_CHUNK_DIR={fallback}\n"
            "Then restart with: sudo python run.py"
        )
    if "permission denied" in lower:
        return (
            "tcpdump needs capture privileges. Run: sudo python run.py — or:\n"
            "  sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)"
        )
    return live_capture_privilege_hint()
