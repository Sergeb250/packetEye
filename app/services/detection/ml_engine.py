"""Isolation Forest anomaly detection with SHAP explanations."""

import logging
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "bytes_total_log",
    "packets_total",
    "duration_ms_log",
    "bytes_per_packet",
    "iat_mean",
    "iat_std",
    "dst_port",
    "dst_port_entropy",
    "is_external_dst",
    "time_of_day_hour",
    "protocol_encoded",
]

PROTOCOL_MAP = {"TCP": 1, "UDP": 2, "ICMP": 3}


def _port_entropy(flows_df: pd.DataFrame) -> dict:
    entropy_by_src = {}
    for src, group in flows_df.groupby("src_ip"):
        ports = group["dst_port"].tolist()
        if not ports:
            entropy_by_src[src] = 0.0
            continue
        counts = {}
        for p in ports:
            counts[p] = counts.get(p, 0) + 1
        total = len(ports)
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
        entropy_by_src[src] = entropy
    return entropy_by_src


def build_feature_matrix(flows: list) -> pd.DataFrame:
    rows = []
    df = pd.DataFrame(flows)
    port_entropy = _port_entropy(df) if len(df) else {}

    for f in flows:
        bytes_total = (f.get("bytes_sent", 0) or 0) + (f.get("bytes_recv", 0) or 0)
        packets_total = (f.get("packets_sent", 0) or 0) + (f.get("packets_recv", 0) or 0)
        duration = f.get("duration_ms", 0) or 0
        start = f.get("start_time")
        hour = start.hour if start and hasattr(start, "hour") else 12

        rows.append(
            {
                "flow_id": f.get("id"),
                "bytes_total_log": math.log1p(bytes_total),
                "packets_total": packets_total,
                "duration_ms_log": math.log1p(duration),
                "bytes_per_packet": bytes_total / max(packets_total, 1),
                "iat_mean": f.get("iat_mean", 0) or 0,
                "iat_std": f.get("iat_std", 0) or 0,
                "dst_port": f.get("dst_port", 0) or 0,
                "dst_port_entropy": port_entropy.get(f.get("src_ip"), 0),
                "is_external_dst": 1 if f.get("is_external_dst") else 0,
                "time_of_day_hour": hour,
                "protocol_encoded": PROTOCOL_MAP.get(f.get("protocol", ""), 0),
            }
        )
    return pd.DataFrame(rows)


def normalize_if_score(raw_score: float) -> float:
    """Convert Isolation Forest score (-1 to 0) to 0-10 scale."""
    return min(10.0, max(0.0, round((-raw_score) * 10, 2)))


class MLEngine:
    def __init__(self, model_path: Path | None = None, threshold: float = 7.5, max_flows: int = 50000):
        self.model_path = model_path
        self.threshold = threshold
        self.max_flows = max_flows
        self.model = None
        if model_path and model_path.exists():
            try:
                import joblib

                self.model = joblib.load(model_path)
            except Exception as exc:
                logger.warning("Could not load baseline model: %s", exc)

    def score_flows(self, flows: list) -> list[dict]:
        if not flows:
            return []

        sample = flows[: self.max_flows]
        features_df = build_feature_matrix(sample)
        if features_df.empty:
            return []

        X = features_df[FEATURE_NAMES].values

        if self.model is None:
            n = len(sample)
            train_size = max(10, int(n * 0.8))
            model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            model.fit(X[:train_size])
            scores = model.decision_function(X)
            explanations = self._simple_explanations(features_df, scores)
        else:
            model = self.model
            scores = model.decision_function(X)
            explanations = self._simple_explanations(features_df, scores)

        results = []
        for i, flow in enumerate(sample):
            norm_score = normalize_if_score(float(scores[i]))
            results.append(
                {
                    "flow_id": flow.get("id"),
                    "anomaly_score": norm_score,
                    "explanation": explanations[i],
                    "flagged": norm_score >= self.threshold,
                }
            )
        return results

    def _simple_explanations(self, features_df: pd.DataFrame, scores: np.ndarray) -> list[str]:
        explanations = []
        means = features_df[FEATURE_NAMES].mean()
        for i, row in features_df.iterrows():
            deviations = []
            for feat in FEATURE_NAMES:
                if means[feat] != 0:
                    ratio = abs(row[feat] - means[feat]) / (abs(means[feat]) + 1e-6)
                    if ratio > 2:
                        deviations.append((feat, ratio))
            deviations.sort(key=lambda x: x[1], reverse=True)
            if deviations:
                top = deviations[0][0].replace("_", " ")
                explanations.append(
                    f"This flow was flagged due to unusual {top} compared to baseline traffic."
                )
            else:
                explanations.append("This flow deviates from the normal traffic profile.")
        return explanations
