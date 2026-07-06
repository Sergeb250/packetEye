#!/usr/bin/env bash
# packetEye NIDS + ML soak test — runs until Ctrl+C or SIGTERM.
#
# Rotates ALL 13 CIC-style attack patterns (portscan, bot, DDoS, …, arp),
# drives live capture + ML, and prints per-pattern alert coverage.
#
# Usage:
#   ./scripts/run_nids_soak_test.sh
#   ./scripts/run_nids_soak_test.sh --interface eth0 --rotate 12
#   ./scripts/run_nids_soak_test.sh --no-lab          # real traffic only
#   ./scripts/run_nids_soak_test.sh --mode tcpdump --interface eth1
#   PACKETEYE_URL=http://127.0.0.1:5050 ./scripts/run_nids_soak_test.sh
#
# Requires packetEye running (python run.py) and LIVE_MONITOR_ENABLED=true.
# Synthetic attacks require CAPTURE_LAB_ENABLED=true in .env (Linux/WSL sensor).

set -euo pipefail

BASE_URL="${PACKETEYE_URL:-http://127.0.0.1:5050}"
MODE="${MODE:-suricata}"
INTERFACE="${INTERFACE:-}"
EVE_PATH="${EVE_PATH:-}"
WITH_LAB=1
POLL_SEC="${POLL_SEC:-5}"
ROTATE_SEC="${ROTATE_SEC:-12}"
STOP_LIVE=1
AUTO_CAPTURE=""

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \?//'
  echo
  echo "Options:"
  echo "  --url URL           packetEye base URL (default: $BASE_URL)"
  echo "  --mode MODE         suricata | tcpdump (default: suricata)"
  echo "  --interface IFACE   capture interface (e.g. eth0, eth1)"
  echo "  --eve-path PATH     Suricata eve.json (monitor external Suricata)"
  echo "  --no-lab            Do not start synthetic lab traffic"
  echo "  --no-auto-capture   Do not start Suricata/tcpdump — tail existing EVE only"
  echo "  --keep-live         Leave live ML session running after stop"
  echo "  --poll SEC          Status poll interval (default: 5)"
  echo "  --rotate SEC        Seconds per attack pattern (default: 12)"
  echo "  -h, --help          Show this help"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) BASE_URL="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --interface) INTERFACE="$2"; shift 2 ;;
    --eve-path) EVE_PATH="$2"; shift 2 ;;
    --no-lab) WITH_LAB=0; shift ;;
    --no-auto-capture) AUTO_CAPTURE=false; shift ;;
    --keep-live) STOP_LIVE=0; shift ;;
    --poll) POLL_SEC="$2"; shift 2 ;;
    --rotate) ROTATE_SEC="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required." >&2
  exit 1
fi

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u; }

print_coverage() {
  local status_json="$1"
  python3 - <<'PY' "$status_json"
import json, sys
d = json.loads(sys.argv[1])
rows = d.get("pattern_coverage") or []
if not rows:
    print("COVERAGE: (waiting for lab patterns…)")
    sys.exit(0)
parts = []
for r in rows:
    ml = "✓ML" if r.get("alerted_ml") else "·"
    su = "✓Suri" if r.get("alerted_suricata") else "·"
    parts.append(f"{r.get('pattern')} {ml} {su}")
print("COVERAGE: " + " | ".join(parts))
active = (d.get("stats") or {}).get("current_pattern") or (d.get("lab_status") or {}).get("current_pattern")
if active:
    elapsed = d.get("elapsed_sec", 0)
    print(f"ACTIVE: {active} (soak {elapsed:.0f}s)")
PY
}

cleanup() {
  echo
  echo "[$(ts)] Stopping NIDS soak test..."
  payload="{\"stop_live\":$([ "$STOP_LIVE" = 1 ] && echo true || echo false)}"
  final="$(curl -sf -X POST "${BASE_URL}/api/nids-test/stop" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null || true)"
  echo "[$(ts)] Final coverage:"
  if [[ -n "$final" ]]; then
    print_coverage "$final"
  fi
  echo "[$(ts)] Done."
  exit 0
}
trap cleanup INT TERM

echo "=== packetEye NIDS + ML malicious traffic soak ==="
echo "API:        $BASE_URL"
echo "Mode:       $MODE"
echo "Lab traffic: $([ "$WITH_LAB" = 1 ] && echo all 13 patterns || echo disabled)"
echo "Rotate:     ${ROTATE_SEC}s per pattern"
echo "Poll:       ${POLL_SEC}s (Ctrl+C to stop)"
echo

if ! curl -sf "${BASE_URL}/api/live/config" >/dev/null; then
  echo "Cannot reach packetEye at $BASE_URL — start the app first: python run.py" >&2
  exit 1
fi

json='{'
json+="\"mode\":\"${MODE}\""
json+=",\"with_lab\":$([ "$WITH_LAB" = 1 ] && echo true || echo false)"
json+=",\"poll_sec\":${POLL_SEC}"
json+=",\"rotate_sec\":${ROTATE_SEC}"
json+=",\"stop_live_on_exit\":$([ "$STOP_LIVE" = 1 ] && echo true || echo false)"
if [[ -n "$INTERFACE" ]]; then json+=",\"interface\":\"${INTERFACE}\""; fi
if [[ -n "$EVE_PATH" ]]; then json+=",\"eve_path\":\"${EVE_PATH}\""; fi
if [[ -n "$AUTO_CAPTURE" ]]; then json+=",\"auto_capture\":${AUTO_CAPTURE}"; fi
json+='}'

echo "[$(ts)] Starting soak test (all malicious patterns)..."
resp="$(curl -sf -X POST "${BASE_URL}/api/nids-test/start" \
  -H "Content-Type: application/json" \
  -d "$json")" || {
  echo "Start failed. Is LIVE_MONITOR_ENABLED=true and CAPTURE_LAB_ENABLED=true?" >&2
  exit 1
}

SESSION_ID="$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null || true)"
echo "[$(ts)] Started session=${SESSION_ID:-?}"
echo "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"
echo
echo "--- live stats + coverage (until stopped) ---"

while true; do
  status="$(curl -sf "${BASE_URL}/api/nids-test/status")" || {
    echo "[$(ts)] status poll failed" >&2
    sleep "$POLL_SEC"
    continue
  }
  python3 - <<'PY' "$status" 2>/dev/null || echo "$status"
import json, sys
from datetime import datetime
d = json.loads(sys.argv[1])
st = d.get("stats") or {}
al = (st.get("alerts") or {})
elapsed = d.get("elapsed_sec", 0)
ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
lab = "lab=on" if d.get("lab_running") else "lab=off"
pat = st.get("current_pattern") or (d.get("lab_status") or {}).get("current_pattern") or "-"
print(
    f"[{ts}] elapsed={elapsed:.0f}s flows={st.get('total_flows',0)} "
    f"findings={st.get('total_findings',0)} "
    f"alerts(ml={al.get('ml',0)}, suricata={al.get('suricata',0)}, total={al.get('total',0)}) "
    f"{lab} pattern={pat}"
)
recent = al.get("recent") or []
for a in recent[-3:]:
    print(f"  · {a.get('type','?')} {a.get('severity','?')} "
          f"{a.get('src_ip','?')}→{a.get('dst_ip','?')} "
          f"{(a.get('explanation') or a.get('signature') or '')[:72]}")
PY
  print_coverage "$status"
  sleep "$POLL_SEC"
done
