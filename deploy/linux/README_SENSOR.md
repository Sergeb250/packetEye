# packetEye — Single Linux Sensor Deployment

Run the whole platform on **one Linux box** receiving mirrored (SPAN/TAP) traffic.
Analysts operate everything from the browser — no terminal for capture.

## Topology

```
[ Switch SPAN / TAP ] --mirror--> [ eth1 ]  packetEye sensor
                                     │
                                     ├─ Suricata  → eve.json (rule alerts + flow events) → ML monitor
                                     └─ tcpdump   → rotating PCAP chunks → chunk watcher → analysis
```

- **Management NIC** (eth0): SSH + dashboard access, has an IP.
- **Capture NIC** (eth1): connected to the mirror port; no IP needed, set as `CAPTURE_INTERFACE`.

## Install

```bash
git clone <repo> /opt/packetEye && cd /opt/packetEye
sudo bash deploy/linux/install_sensor.sh
```

The installer adds `suricata` + `tcpdump`, builds the venv, and runs
`setcap cap_net_raw,cap_net_admin=eip` on both binaries so capture works
without full root at runtime.

## Configure `.env`

```env
CAPTURE_INTERFACE=eth1
CAPTURE_MODE=suricata            # default; tcpdump is the fallback
ENRICHMENT_MODE=on_investigate   # OSINT runs per alert, not on every flow
ML_ANOMALY_THRESHOLD=5.0         # from scripts/tune_threshold.py
LIVE_MONITOR_ENABLED=true

# Optional
ALERT_WEBHOOK_URL=https://discord.com/api/webhooks/...
ALERT_WEBHOOK_MIN_SEVERITY=high
AUTO_INVESTIGATE_LIVE=false      # auto-OSINT on high/critical live alerts
NVIDIA_API_KEY=...               # enables the SOC chatbot + LLM report
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
```

## Run

Dev: `python run.py` → open `http://<mgmt-ip>:5000`.
Prod: install the systemd unit (see `install_sensor.sh` output), served by gunicorn.

## Dashboard workflow (no terminal)

1. **Live Monitor → Traffic Capture** — pick mode (Suricata or tcpdump) and interface, click **Start capture**.
2. **Start ML Live Monitor** — scores Suricata flow events in real time; Suricata rule alerts and ML anomalies share one feed. A signature + ML anomaly on the same hosts is auto-escalated to a **correlation** alert.
3. On any alert, click **Investigate** → VirusTotal / AbuseIPDB / WHOIS / GeoIP results appear in the side panel.
4. High/critical alerts are pushed to your **Discord webhook** if configured.

## Suricata vs tcpdump

| | Suricata (default) | tcpdump (fallback) |
|--|--|--|
| Output | eve.json: rule alerts + flow events | rotating PCAP chunks |
| ML | Live per-flow scoring | Per-chunk after each chunk closes |
| Rule alerts | Yes (signatures) | No (ML + YAML rules only) |
| Use when | Suricata installed & configured | Suricata unavailable, or you want raw PCAP retained |

tcpdump chunks rotate every `TCPDUMP_CHUNK_SECONDS` and are auto-analyzed once
closed; capture never stops. Old chunks beyond `TCPDUMP_CHUNK_KEEP` are pruned.

## Permissions troubleshooting

If capture fails to start with a permission error:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v suricata)"
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
```
Or run the app with sudo (not recommended for production).
