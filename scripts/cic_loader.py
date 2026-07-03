"""Load CIC-IDS2017 Network-Flows from nids-datasets download layout."""

import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PARQUET = ROOT / "CIC-IDS2017" / "Network-Flows" / "CICIDS_Flow.parquet"

# CIC-IDS2017 capture dates (day name -> date)
CIC_DAY_DATES = {
    "Monday": "2017-07-03",
    "Tuesday": "2017-07-04",
    "Wednesday": "2017-07-05",
    "Thursday": "2017-07-06",
    "Friday": "2017-07-07",
}

FEATURE_COLUMNS = [
    "flow_id",
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Fwd IAT Mean",
    "attack_label",
]


def ensure_downloaded() -> Path:
    """Download CIC-IDS2017 Network-Flows parquet if missing."""
    if DEFAULT_PARQUET.exists():
        return DEFAULT_PARQUET

    from nids_datasets import Dataset

    logger.info("Downloading CIC-IDS2017 Network-Flows...")
    data = Dataset(dataset="CIC-IDS2017", subset=["Network-Flows"], files="all")
    data.download()
    if not DEFAULT_PARQUET.exists():
        raise FileNotFoundError(f"Expected parquet at {DEFAULT_PARQUET} after download")
    return DEFAULT_PARQUET


def load_cic_flows(day: str | None = None, columns: list[str] | None = None) -> pd.DataFrame:
    """Load flows; optionally filter by weekday name using Timestamp."""
    path = ensure_downloaded()
    use_cols = columns
    if use_cols is None:
        import pyarrow.parquet as pq

        available = pq.read_schema(path).names
        use_cols = [c for c in FEATURE_COLUMNS if c in available]

    logger.info("Reading %s (columns=%d)...", path.name, len(use_cols))
    df = pd.read_parquet(path, columns=use_cols, engine="pyarrow")

    if "attack_label" in df.columns:
        df["Label"] = df["attack_label"].astype(str).str.strip()
    elif "Label" not in df.columns:
        raise ValueError("No Label/attack_label column in CIC data")

    if day:
        day_date = CIC_DAY_DATES.get(day)
        if not day_date:
            raise ValueError(f"Unknown day {day}; use Monday-Friday")
        if "Timestamp" not in df.columns:
            logger.warning("No Timestamp column; cannot filter by %s", day)
        else:
            ts = pd.to_datetime(df["Timestamp"], errors="coerce")
            target = pd.Timestamp(day_date).date()
            before = len(df)
            filtered = df[ts.dt.date == target].copy()
            logger.info("Filtered %s (%s): %d -> %d rows", day, day_date, before, len(filtered))
            if len(filtered) == 0:
                logger.warning(
                    "Day filter returned 0 rows (timestamps may not match CIC calendar dates). "
                    "Using full dataset."
                )
                df.attrs["day_filtered"] = False
            else:
                df = filtered
                df.attrs["day_filtered"] = True
    else:
        df.attrs["day_filtered"] = False

    return df.reset_index(drop=True)
