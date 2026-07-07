# Retraining on the Full CIC-IDS2017 Feature Set (78 features)

This guide walks through retraining packetEye's Isolation Forest on the
**full CIC-IDS2017 feature set** (schema v4, 78 features) instead of the
legacy 20-feature set (schema v3), then tuning and applying the alert
threshold. Nothing in the app switches until you run these steps — the code
supports both feature sets and picks the right one from the saved
`ml_models/feature_schema.json`.

## Why retrain

The current benchmark (`ml_models/benchmark_results.json`, legacy 20
features) shows the gap is **feature depth**, not threshold math:

| Metric | Value |
|---|---|
| Overall attack recall @ threshold 5.0 | **36.4%** |
| PortScan recall | **0.6%** |
| DDoS / DoS GoldenEye recall | 86.6% / 93.7% |

Port scans and brute force live in features the legacy set doesn't carry —
TCP flag counts (SYN without ACK), packet-length min/max/std, init window
sizes, per-direction IATs. The full set includes all of them.

### Important: the threshold is a calibrated 0–10 score, not 0.35

If you've seen advice to set `ML_ANOMALY_THRESHOLD=0.35` — **that does not
apply to packetEye.** This app maps IsolationForest's decision function onto
a calibrated **0–10 scale where 5.0 = the model's decision boundary**
(`app/services/detection/ml_engine.py`, `ScoreCalibrator`, anchored by
`ml_models/score_calibration.json`). Setting 0.35 would flag essentially
every flow's calibrated score as anomalous — or on this scale, suppress
nothing meaningfully. Always take the threshold from
`scripts/tune_threshold.py` output (typically between 4.5 and 6.0).

The pre-existing `ml_models/recommended_threshold.json` showing 0% recall at
every threshold is a stale artifact from an old, broken run — it is
overwritten the first time you re-run `tune_threshold.py`.

## Feature-set summary

| | Legacy (v3) | Full (v4) |
|---|---|---|
| Features | 20 engineered | 78 CIC-native columns |
| Units | ms / seconds, log-scaled | CIC-native (µs durations/IATs), raw passthrough |
| Schema file | `feature_schema.json` version 3 | version 4 + `feature_set: full` |
| Extra artifact | — | `feature_fill_values.json` (training medians for live inference) |
| Live inference | all features derivable | derivable features computed; rest median-filled |

## 1. Prerequisites

- `pip install -r requirements.txt` (needs `nids-datasets`, `pyarrow`,
  `scikit-learn`, `pandas`).
- **Disk:** ~400 MB for `CIC-IDS2017/Network-Flows/CICIDS_Flow.parquet`.
- **RAM:** ~6–8 GB free for the full-feature load (2.8 M rows × 78 float
  columns). Close the live monitor / browser tabs on small sensor boxes, or
  train on a workstation and copy `ml_models/` across.
- Run everything from the repo root with the app's virtualenv activated.

## 2. Download the dataset (skipped if already present)

The loader auto-downloads on first use, or force it up front:

```bash
python -c "from scripts.cic_loader import ensure_downloaded; print(ensure_downloaded())"
```

## 3. Train

```bash
python scripts/train_baseline.py --feature-set full --contamination 0.08
```

Defaults already match the recommended setup: `n_estimators=300`,
`max_samples=4096` (small per-tree samples + many trees is what makes subtle
anomalies isolate; do not raise `max_samples` into the tens of thousands).

This writes to `ml_models/`:

- `isolation_forest_base.pkl`, `feature_scaler.pkl`
- `feature_schema.json` — version 4, `feature_set: full` (this is what flips
  the app to the full builder)
- `score_calibration.json` — new 0–10 anchoring for this model
- `feature_fill_values.json` — per-feature training medians used by live
  inference for stats capture can't measure
- `training_metadata.json`

## 4. Tune the threshold

```bash
python scripts/tune_threshold.py            # auto-detects feature set from the schema
```

Sweeps calibrated thresholds 3.0–9.0 and writes
`ml_models/recommended_threshold.json` with the best-F1 point subject to a
benign false-positive cap of 10%. The log line at the end tells you the value.

## 5. Evaluate

```bash
python scripts/evaluate_model.py            # auto-detects feature set + tuned threshold
```

Writes `ml_models/benchmark_results.json` with overall and per-attack-label
recall. **Check `PortScan` and `SSH-Patator` / `FTP-Patator` recall
specifically** — those are the classes the full feature set exists to fix.
If PortScan recall is still near zero, see Troubleshooting.

## 6. Apply the threshold

Put the recommended value in `.env` (calibrated 0–10 scale):

```env
# from ml_models/recommended_threshold.json "recommended.threshold"
ML_ANOMALY_THRESHOLD=4.75
```

## 7. Restart and verify live

1. Restart the app (the live monitor constructs its `MLEngine` at session
   start; the schema flip is picked up automatically).
2. Start capture + ML live monitor as usual.
3. Generate lab traffic (Lab tab → portscan pattern, or
   `nmap -sS <lab-target>` from another host).
4. Expect `Live ML Anomaly` findings for the scan; check the score sits
   above your threshold in the alert detail.

## Live-inference parity (what live can and cannot measure)

Suricata EVE flow records and PCAP parsing don't expose every CICFlowMeter
statistic. The full builder computes what each source can derive and fills
the rest with **training medians** (`feature_fill_values.json`) so
unmeasured dimensions sit at "typical benign" instead of a misleading 0.

| Source | Derived live | Median-filled |
|---|---|---|
| Uploaded PCAP (`pcap_parser`) | durations, per-direction bytes/packets/IATs, packet-length min/max/std, TCP flag counts, header lengths, init windows, act_data/min_seg | bulk rates, active/idle windows, CWE flag |
| Suricata EVE flows | durations, per-direction bytes/packets, mean IAT, SYN/FIN/RST presence | packet-length stats, remaining flags, header/window stats, bulk, active/idle |
| Scapy fallback | durations, combined bytes/packets, IAT mean/std/min/max, packet-length min/max/std | per-direction stats, flags, windows, bulk, active/idle |

Consequence: **offline PCAP analysis gets the most model fidelity; EVE-based
live scoring is best-effort.** Anomalies that manifest purely in
median-filled dimensions won't be visible live — but scan/bruteforce signals
(flags, lengths, rates, IATs) are exactly the ones live capture does carry.

## Troubleshooting

- **`Feature schema mismatch: schema names [...] are not produced ...` at
  startup** — the schema file names features no builder produces (usually a
  hand-edited or truncated file). Retrain, or restore a known-good
  `feature_schema.json`.
- **`Full-feature schema without feature_fill_values.json` warning** — you
  copied a v4 model without its fill file; live scores will treat
  unmeasured features as 0. Copy `feature_fill_values.json` alongside the
  other artifacts or retrain.
- **Scores all ~5.0 or clipped at 10 after retrain** — stale
  `score_calibration.json` from the previous model. It's rewritten by
  training; if you copied artifacts manually, copy the calibration file too.
- **Stale scaler** (`X has N features, but MinMaxScaler is expecting M`) —
  mixed artifact generations. All five artifacts (`.pkl` ×2 + 3 JSON) must
  come from the same training run.
- **MemoryError during training** — train on a bigger machine and copy
  `ml_models/` over; artifact loading on the sensor is cheap.
- **PortScan recall still low after retrain** — confirm the benchmark ran
  with `feature_set: full` (top of `benchmark_results.json`), then retune
  the threshold; scan flows score in a band just above the boundary, so an
  over-conservative threshold hides them. Attack-specific ensemble models
  are the next step beyond this baseline.
- **SQLite "database is locked" during long training runs on the sensor** —
  train while the live monitor is stopped, or point `DATABASE_URL` at
  Postgres for production sensors.
- **`train_tracker.py`** currently trains the legacy 20-feature set only;
  use `train_baseline.py --feature-set full` for v4 models.

## Recommended `.env` for live stability (documentation — set per host)

```env
# --- database pool (defaults shown; raise for busy sensors) ---
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_TIMEOUT=45

# --- live LLM triage: sequential by default; keep it that way ---
LLM_LIVE_PARALLEL_TRIAGE=false
LLM_LIVE_PACKET_MAX_TOKENS=128
# Disable OpenRouter entirely while the account has no credits —
# otherwise it is auto-parked for 30 min after each 402 anyway.
OPENROUTER_ENABLED=false

# --- ML threshold: ONLY after tune_threshold.py, calibrated 0-10 scale ---
# ML_ANOMALY_THRESHOLD=4.75
```

## Rolling back to the legacy model

```bash
python scripts/train_baseline.py --feature-set legacy
python scripts/tune_threshold.py
python scripts/evaluate_model.py
```

The schema drops back to v3 and the app resumes the 20-feature builder on
the next restart.
