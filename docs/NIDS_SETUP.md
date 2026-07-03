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
