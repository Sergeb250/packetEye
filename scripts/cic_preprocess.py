"""CIC-IDS2017 preprocessing helpers for training and evaluation."""

import logging

import numpy as np
import pandas as pd

from app.services.detection.features import FEATURE_NAMES, build_feature_matrix_from_cic

logger = logging.getLogger(__name__)


def clean_cic_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Drop duplicates, infinities, and rows with missing feature values."""
    initial = len(df)
    df = df.drop_duplicates()
    df = df.replace([np.inf, -np.inf], np.nan)

    label_col = "Label" if "Label" in df.columns else "attack_label" if "attack_label" in df.columns else None
    if label_col:
        df[label_col] = df[label_col].astype(str).str.strip()
        if label_col != "Label":
            df["Label"] = df[label_col]

    feature_df = build_feature_matrix_from_cic(df)
    mask = feature_df[FEATURE_NAMES].notna().all(axis=1)
    df = df.iloc[mask.to_numpy()].reset_index(drop=True)

    logger.info("Cleaned CIC data: %d -> %d rows", initial, len(df))
    return df


def filter_benign(df: pd.DataFrame) -> pd.DataFrame:
    if "Label" not in df.columns:
        raise ValueError("Label column required")
    benign = df[df["Label"].str.upper() == "BENIGN"].copy()
    logger.info("BENIGN rows: %d / %d", len(benign), len(df))
    return benign


def is_attack_label(label: str) -> bool:
    return str(label).strip().upper() != "BENIGN"
