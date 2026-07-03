#!/usr/bin/env python3
"""Verify Phase 0-4 NIDS prerequisites and artifacts."""

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ML_DIR = ROOT / "ml_models"

REQUIRED_PACKAGES = [
    "pandas",
    "numpy",
    "sklearn",
    "joblib",
    "nids_datasets",
    "pyarrow",
]

REQUIRED_ARTIFACTS = [
    "isolation_forest_base.pkl",
    "feature_scaler.pkl",
    "feature_schema.json",
    "score_calibration.json",
    "training_metadata.json",
]

OPTIONAL_ARTIFACTS = [
    "benchmark_results.json",
    "recommended_threshold.json",
]


def check_packages() -> list[str]:
    failures = []
    for pkg in REQUIRED_PACKAGES:
        try:
            importlib.import_module(pkg)
        except ImportError:
            failures.append(pkg)
    return failures


def main():
    print("packetEye NIDS setup verification\n" + "=" * 40)

    missing_pkgs = check_packages()
    if missing_pkgs:
        print("FAIL missing Python packages:", ", ".join(missing_pkgs))
        print("  Fix: pip install -r requirements.txt")
    else:
        print("OK   Python packages installed")

    print()
    for name in REQUIRED_ARTIFACTS:
        path = ML_DIR / name
        if path.exists():
            print(f"OK   {name}")
        else:
            print(f"MISS {name}  -> run: python scripts/train_baseline.py")

    print()
    for name in OPTIONAL_ARTIFACTS:
        path = ML_DIR / name
        if path.exists():
            print(f"OK   {name}")
        else:
            print(f"SKIP {name}  -> run: python scripts/evaluate_model.py")

    db_path = ROOT / "packeteye.db"
    if db_path.exists():
        print(f"\nNOTE Existing DB found: {db_path}")
        print("     Run: python scripts/migrate_db.py  (if upgrading from older schema)")

    print("\nNext steps:")
    if missing_pkgs:
        print("  1. pip install -r requirements.txt")
    if not (ML_DIR / "isolation_forest_base.pkl").exists():
        print("  2. python scripts/train_tracker.py   (interactive, recommended)")
        print("     or: python scripts/train_baseline.py")
        print("  3. python scripts/tune_threshold.py  (recommends ML_ANOMALY_THRESHOLD)")
        print("  4. python scripts/evaluate_model.py  (benchmarks at the tuned threshold)")
    else:
        print("  1. python scripts/evaluate_model.py  (if not done)")
        print("  2. python run.py  and upload a PCAP to test ML scoring")
        print("  3. Continue to Phase 5: enable LIVE_MONITOR_ENABLED and Suricata")

    if missing_pkgs:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
