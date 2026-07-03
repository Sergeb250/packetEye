"""Flask development server entry point."""

import argparse
import errno
import os
import socket
import sys

from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

# Ports to try when the requested one is blocked. Windows reserves whole
# ranges of ports for Hyper-V/WinNAT (binding there fails with WinError
# 10013: "access a socket in a way forbidden by its access permissions").
# 5000-5099 commonly falls inside a reserved range.
FALLBACK_PORTS = [5050, 8000, 8080, 8888, 3000, 7000]

_BLOCKED_ERRNOS = {errno.EACCES, errno.EADDRINUSE, 10013, 10048}


def _port_available(host: str, port: int) -> bool:
    """Probe with the same exclusive semantics Werkzeug uses on Windows."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((host, port))
        return True
    except OSError:
        return False


def _candidates(requested: int) -> list[int]:
    return [requested] + [p for p in FALLBACK_PORTS if p != requested]


def _serve(host: str, requested: int, debug: bool) -> None:
    last_error = None
    for port in _candidates(requested):
        if not _port_available(host, port):
            continue
        if port != requested:
            print(
                f" ! Port {requested} is blocked (WinError 10013 usually means it sits in a "
                f"Windows reserved port range — list them with:\n"
                f"   netsh interface ipv4 show excludedportrange protocol=tcp"
            )
        print(f" * packetEye starting on http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
        try:
            app.run(host=host, port=port, debug=debug)
            return
        except (OSError, SystemExit) as exc:
            # The probe passed but the real bind was still refused (reserved
            # range edge case) — move on to the next candidate port.
            code = getattr(exc, "errno", None) or getattr(exc, "winerror", None)
            if isinstance(exc, OSError) and code in _BLOCKED_ERRNOS:
                print(f" ! Bind to port {port} refused (error {code}), trying next port...")
                last_error = exc
                continue
            raise
    sys.exit(
        f"No usable port found (tried {_candidates(requested)}). Last error: {last_error}. "
        "Pick one manually: py run.py --port=<port>"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the packetEye dev server")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)))
    parser.add_argument("--no-debug", action="store_true", help="Disable Flask debug mode")
    args = parser.parse_args()

    if sys.platform != "win32" and app.config.get("LIVE_MONITOR_ENABLED"):
        try:
            from app.services.capture.privileges import live_capture_privilege_hint, running_as_root

            if not running_as_root():
                hint = live_capture_privilege_hint()
                if hint:
                    print(f" ! {hint}")
        except Exception:
            pass

    _serve(args.host, args.port, debug=not args.no_debug)
