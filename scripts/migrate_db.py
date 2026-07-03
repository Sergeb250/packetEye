#!/usr/bin/env python3
"""Add NIDS columns to existing SQLite/PostgreSQL databases."""

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FLOW_COLUMNS = [
    ("iat_mean", "REAL DEFAULT 0"),
    ("iat_std", "REAL DEFAULT 0"),
    ("iat_max", "REAL DEFAULT 0"),
    ("fwd_iat_mean", "REAL DEFAULT 0"),
]

ANALYSIS_COLUMNS = [
    ("source", "VARCHAR(16) DEFAULT 'pcap'"),
]


def migrate_sqlite(db_path: Path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(flows)")
    flow_cols = {row[1] for row in cur.fetchall()}
    for name, col_type in FLOW_COLUMNS:
        if name not in flow_cols:
            cur.execute(f"ALTER TABLE flows ADD COLUMN {name} {col_type}")
            print(f"Added flows.{name}")

    cur.execute("PRAGMA table_info(analyses)")
    analysis_cols = {row[1] for row in cur.fetchall()}
    for name, col_type in ANALYSIS_COLUMNS:
        if name not in analysis_cols:
            cur.execute(f"ALTER TABLE analyses ADD COLUMN {name} {col_type}")
            print(f"Added analyses.{name}")

    conn.commit()
    conn.close()
    print("Migration complete.")


if __name__ == "__main__":
    db = ROOT / "packeteye.db"
    if len(sys.argv) > 1:
        db = Path(sys.argv[1])
    if not db.exists():
        print(f"Database not found: {db}")
        sys.exit(0)
    migrate_sqlite(db)
