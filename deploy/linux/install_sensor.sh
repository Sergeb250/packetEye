#!/usr/bin/env bash
# packetEye Linux sensor installer — single box on mirrored traffic.
# Tested on Ubuntu 22.04+ and Kali. Run from the repo root: sudo bash deploy/linux/install_sensor.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-python3}"

echo "==> packetEye sensor install (repo: $REPO_DIR)"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root (sudo) — capture tools need elevated privileges to install." >&2
    exit 1
fi

echo "==> Installing system packages (suricata, tcpdump, python venv)"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y suricata tcpdump python3-venv python3-pip
else
    echo "!! apt-get not found. Install suricata, tcpdump, and python3-venv manually." >&2
fi

echo "==> Python virtualenv + dependencies"
cd "$REPO_DIR"
if [[ ! -d .venv ]]; then
    "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "==> Granting capture capabilities (no full sudo needed at runtime)"
for bin in "$(command -v suricata || true)" "$(command -v tcpdump || true)"; do
    if [[ -n "$bin" ]]; then
        setcap cap_net_raw,cap_net_admin=eip "$bin" || echo "!! setcap failed for $bin (capture may need sudo)"
    fi
done

echo "==> Checking ML artifacts"
if [[ ! -f ml_models/isolation_forest_base.pkl ]]; then
    echo "!! No trained model. Run: python scripts/train_baseline.py && python scripts/tune_threshold.py"
fi

if [[ ! -f .env ]]; then
    cp .env.example .env
    echo "==> Created .env from .env.example — edit CAPTURE_INTERFACE and API keys."
fi

cat <<'EOF'

==> Install complete.

Next steps:
  1. Edit .env: set CAPTURE_INTERFACE (your mirror port, e.g. eth1), API keys, ALERT_WEBHOOK_URL.
  2. (If needed) train the model:  python scripts/train_baseline.py && python scripts/tune_threshold.py
  3. Start the app:                python run.py    (or install the systemd unit below)
  4. Open the dashboard → Live Monitor → pick mode + interface → Start capture.

Optional systemd service (starts the web app on boot; capture is started from the browser):
  sudo cp deploy/linux/packeteye-sensor.service /etc/systemd/system/
  sudo systemctl daemon-reload && sudo systemctl enable --now packeteye-sensor
EOF
