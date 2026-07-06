# packetEye NIDS Setup

## Overview

packetEye NIDS uses an Isolation Forest model trained on CIC-IDS2017 BENIGN traffic (all days).
The same model scores uploaded PCAP files and live Suricata flow events.

## Prerequisites

- Python 3.11+
- 8 GB RAM minimum (16 GB recommended for training)
- ~5 GB free disk for CIC-IDS2017 Parquet files
- Suricata (external install, not pip) for live monitoring

## Install Python dependencies

```powershell
cd packetEye
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## Verify setup

```powershell
python scripts/verify_nids_setup.py
```

## Database migration (existing installs)

```powershell
python scripts/migrate_db.py
```

## Train the baseline model

**Interactive pipeline (recommended):**

```powershell
python scripts/train_tracker.py
```

Walks through training, verification, threshold tuning, and benchmark step-by-step.
Type `continue` at each prompt; a final report is printed at the end.

**Quick train only:**

```powershell
python scripts/train_baseline.py
```

This downloads CIC-IDS2017 via `nids-datasets`, trains on all-days BENIGN traffic,
and saves artifacts to `ml_models/`:

- `isolation_forest_base.pkl` — 300 trees × 4096 samples/tree, contamination 0.05
- `feature_scaler.pkl`
- `feature_schema.json` — 20 features (schema v3)
- `score_calibration.json` — maps decision scores onto the 0–10 alert scale

Expected training time: under 5 minutes on 8 GB RAM.

> Isolation Forest hyperparameters matter: giving each tree the full dataset
> (`max_samples=1.0`) makes trees redundant and collapses recall on subtle
> attacks like port scans. Small per-tree subsamples with more trees is the
> recommended setup; override with `--max-samples` / `--n-estimators` if needed.

## Tune the alert threshold

```powershell
python scripts/tune_threshold.py
```

Sweeps calibrated thresholds 3.0–9.0 against BENIGN vs attack samples,
recommends the best-F1 threshold with benign false positives capped at 10%,
and saves `ml_models/recommended_threshold.json`. Copy the recommended value
into `ML_ANOMALY_THRESHOLD` in `.env`.

## Evaluate the model

```powershell
python scripts/evaluate_model.py
```

Evaluates at the tuned threshold (the same scoring path the app uses) on
all-days labeled data and saves `ml_models/benchmark_results.json` — shown on
the dashboard.

## Environment variables

Copy `.env.example` to `.env` and set:

```
ML_MODEL_PATH=ml_models/isolation_forest_base.pkl
ML_SCALER_PATH=ml_models/feature_scaler.pkl
ML_SCORE_CALIBRATION_PATH=ml_models/score_calibration.json
ML_ANOMALY_THRESHOLD=5.0
ML_TRAIN_ON_PCAP_FALLBACK=false
LIVE_MONITOR_ENABLED=true
SURICATA_EVE_PATH=data/suricata/eve.json
LIVE_INGEST_SURICATA_ALERTS=true
```

On the 0–10 scale, 5.0 is the Isolation Forest decision boundary — flows at or
above the threshold raise ML findings/alerts.

## Suricata

See [SURICATA_SETUP.md](SURICATA_SETUP.md) for EVE JSON flow logging configuration.

## Live Operations Center

Open **Live Monitor** (`/live`) for the unified sensor console:

- **Capture + ML**: Start capture from the Capture tab — ML attaches automatically. tcpdump mode scores Scapy flows; Suricata mode tails `eve.json`.
- **External Suricata**: Running Suricata outside packetEye is auto-detected; EVE path is parsed from `suricata.yaml` when `AUTO_SYNC_EVE=true`.
- **ML tab**: Import external `eve.json` (upload or path) and **Plug into ML** without restarting Suricata.
- **SOC Overview**: Alert queue with severity filters, enhanced inspector (LLM attack classification when `ALERT_ENHANCED_ANALYSIS=true`), OSINT, mark false positive.
- **Lab traffic**: Set `CAPTURE_LAB_ENABLED=true`, start capture+ML, then use the **Lab** tab — single Start/Stop toggle, live attack table, 12+ CIC-IDS2017-style patterns.
- **NIDS soak test**: Rotates **all 13** CIC-style attack patterns, tracks per-pattern ML/Suricata alert coverage until stopped:
  - **Dashboard**: Live Monitor → **Lab** tab → **NIDS + ML Soak Test** (coverage table)
  - **CLI** (Linux/macOS/Git Bash / WSL):

```bash
chmod +x scripts/run_nids_soak_test.sh
./scripts/run_nids_soak_test.sh --interface eth0     # all malicious patterns + monitor
./scripts/run_nids_soak_test.sh --rotate 12          # seconds per pattern (default 12)
./scripts/run_nids_soak_test.sh --no-lab             # real traffic only
./scripts/run_nids_soak_test.sh --mode tcpdump --interface eth1
PACKETEYE_URL=http://127.0.0.1:5050 ./scripts/run_nids_soak_test.sh
```

Requires `python run.py`, `LIVE_MONITOR_ENABLED=true`, and `CAPTURE_LAB_ENABLED=true` for synthetic attacks. Set `LAB_ROTATE_SEC=12` in `.env`.

**Linux sensor:** Scapy + Suricata/tcpdump on mirror port; run as root if needed.

**Windows:** External Suricata + `SURICATA_EVE_PATH` for monitoring; full malicious generation needs WSL/Linux.

One full rotation ≈ 13 × 12s ≈ 2.5 minutes. Watch CLI `COVERAGE:` line or dashboard coverage table.

```
SCAPY_FLOW_IDLE_SEC=5
LIVE_ML_TCPDUMP_ENABLED=true
CAPTURE_LAB_ENABLED=true
LAB_ROTATE_SEC=12
AUTO_SYNC_EVE=true
ALERT_ENHANCED_ANALYSIS=false
LLM_LIVE_ALERT_SYNTHESIS=false
```
