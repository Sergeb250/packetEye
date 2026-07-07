"""Isolation Forest anomaly detection using shared feature contract."""

import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.services.detection.features import (
    FEATURE_NAMES,
    build_feature_matrix,
    build_full_feature_matrix,
    load_feature_fill_values,
    load_feature_schema,  # noqa: F401 — re-exported for existing callers
    load_feature_schema_info,
    validate_feature_schema,  # noqa: F401 — re-exported for existing callers
)

logger = logging.getLogger(__name__)


class ScoreCalibrator:
    """Map IsolationForest decision_function output onto the app's 0-10 scale.

    Anchor points:
      - 5.0  == the model's decision boundary (decision_function == 0, where
               sklearn's predict() flips to -1/anomaly)
      - 0.0  == the most normal score observed on benign training data (d_max)
      - 10.0 == d_min, the anomalous headroom bound saved at training time

    Without a calibration file (older artifacts) a fixed slope is used so the
    boundary still lands at 5.0 — decision_function values typically span
    roughly ±0.2, so slope 25 puts extreme anomalies near 10.
    """

    DEFAULT_SLOPE = 25.0

    def __init__(self, d_min: float | None = None, d_max: float | None = None):
        valid = (
            d_min is not None
            and d_max is not None
            and d_min < 0 < d_max
        )
        self.d_min = float(d_min) if valid else None
        self.d_max = float(d_max) if valid else None

    @property
    def is_calibrated(self) -> bool:
        return self.d_min is not None

    @classmethod
    def load(cls, path: Path | None) -> "ScoreCalibrator":
        if not path or not Path(path).exists():
            return cls()
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            return cls(d_min=data.get("d_min"), d_max=data.get("d_max"))
        except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
            logger.warning("Could not load score calibration from %s: %s", path, exc)
            return cls()

    def normalize(self, raw_score: float) -> float:
        d = float(raw_score)
        if self.is_calibrated:
            if d >= 0:
                score = 5.0 * (1.0 - d / self.d_max)
            else:
                score = 5.0 + 5.0 * (d / self.d_min)
        else:
            score = 5.0 - d * self.DEFAULT_SLOPE
        return min(10.0, max(0.0, round(score, 2)))

    def normalize_array(self, raw_scores: np.ndarray) -> np.ndarray:
        d = np.asarray(raw_scores, dtype=float)
        if self.is_calibrated:
            scores = np.where(
                d >= 0,
                5.0 * (1.0 - d / self.d_max),
                5.0 + 5.0 * (d / self.d_min),
            )
        else:
            scores = 5.0 - d * self.DEFAULT_SLOPE
        return np.clip(np.round(scores, 2), 0.0, 10.0)


def normalize_if_score(raw_score: float) -> float:
    """Uncalibrated fallback mapping (5.0 == model decision boundary)."""
    return ScoreCalibrator().normalize(raw_score)


def compute_score_calibration(
    model, X_scaled: np.ndarray, max_rows: int = 500_000, random_state: int = 42
) -> dict:
    """Derive 0-10 calibration bounds from benign training scores.

    d_min gets 1.5x headroom beyond the worst benign score so attack flows —
    typically far more anomalous than any benign flow — spread over 5-10
    instead of all clipping at 10.
    """
    X = np.asarray(X_scaled, dtype=float)
    if len(X) > max_rows:
        rng = np.random.default_rng(random_state)
        X = X[rng.choice(len(X), size=max_rows, replace=False)]

    d = model.decision_function(X)
    raw_min = float(d.min())
    raw_max = float(d.max())
    quantiles = {
        f"p{q}": float(np.quantile(d, q / 100.0))
        for q in (0.1, 1, 5, 50, 95, 99, 99.9)
    }
    return {
        "version": 1,
        "d_min": raw_min * 1.5 if raw_min < 0 else -0.1,
        "d_max": raw_max if raw_max > 0 else 0.1,
        "benign_decision_scores": {"min": raw_min, "max": raw_max, **quantiles},
        "boundary_score": 5.0,
        "note": "0-10 anomaly scale; 5.0 == IsolationForest decision boundary (predict == -1)",
    }


def save_score_calibration(calibration: dict, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(calibration, indent=2), encoding="utf-8")


class MLEngine:
    def __init__(
        self,
        model_path: Path | None = None,
        scaler_path: Path | None = None,
        schema_path: Path | None = None,
        calibration_path: Path | None = None,
        threshold: float = 5.0,
        max_flows: int = 50000,
        train_on_pcap_fallback: bool = False,
        strict_schema: bool = True,
    ):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.schema_path = schema_path
        self.threshold = threshold
        self.max_flows = max_flows
        self.train_on_pcap_fallback = train_on_pcap_fallback
        self.strict_schema = strict_schema
        self.model = None
        self.scaler = None
        self.feature_names = list(FEATURE_NAMES)
        self.feature_set = "legacy"
        self.fill_values: dict = {}
        self.calibrator = ScoreCalibrator.load(calibration_path)

        if schema_path and schema_path.exists():
            try:
                info = load_feature_schema_info(schema_path)
                self.feature_names = info["feature_names"]
                self.feature_set = info["feature_set"]
            except ValueError as exc:
                if strict_schema:
                    raise
                logger.warning("Feature schema validation failed: %s", exc)
            if self.feature_set == "full":
                self.fill_values = load_feature_fill_values(
                    Path(schema_path).with_name("feature_fill_values.json")
                )
                if not self.fill_values:
                    logger.warning(
                        "Full-feature schema without feature_fill_values.json — "
                        "non-derivable live features score as 0 instead of the "
                        "training median. Retrain with train_baseline.py --feature-set full."
                    )

        if model_path and model_path.exists():
            if scaler_path and not scaler_path.exists():
                logger.warning("Baseline model exists but scaler missing at %s", scaler_path)

        if scaler_path and scaler_path.exists():
            try:
                import joblib

                self.scaler = joblib.load(scaler_path)
            except Exception as exc:
                logger.warning("Could not load feature scaler: %s", exc)

        if model_path and model_path.exists():
            try:
                import joblib

                self.model = joblib.load(model_path)
            except Exception as exc:
                logger.warning("Could not load baseline model: %s", exc)

    @property
    def has_baseline(self) -> bool:
        return self.model is not None and self.scaler is not None

    def _transform_features(self, X: np.ndarray) -> np.ndarray:
        if self.scaler is not None:
            return self.scaler.transform(X)
        return X

    def _build_feature_array(self, features_df: pd.DataFrame) -> np.ndarray:
        missing = [c for c in self.feature_names if c not in features_df.columns]
        if missing:
            msg = f"Missing feature columns for inference: {missing}"
            if self.strict_schema:
                raise ValueError(msg)
            logger.warning(msg)
        return features_df[self.feature_names].values.astype(float)

    SCORING_CHUNK_SIZE = 2000

    def score_flows(self, flows: list, progress_callback=None) -> list[dict]:
        """Score flows in chunks so long runs report progress (0-100)."""
        if not flows:
            return []
        sample = flows[: self.max_flows]
        results: list[dict] = []
        total = len(sample)
        for start in range(0, total, self.SCORING_CHUNK_SIZE):
            chunk = sample[start : start + self.SCORING_CHUNK_SIZE]
            results.extend(self._score_batch(chunk))
            if progress_callback:
                progress_callback(min(100, int((start + len(chunk)) * 100 / total)))
        return results

    def _score_batch(self, sample: list) -> list[dict]:
        if not sample:
            return []
        if self.feature_set == "full":
            features_df = build_full_feature_matrix(sample, self.fill_values)
        else:
            features_df = build_feature_matrix(sample)
        if features_df.empty:
            return []

        try:
            X = self._build_feature_array(features_df)
        except ValueError as exc:
            logger.error("ML scoring aborted: %s", exc)
            return []

        if self.model is None:
            if not self.train_on_pcap_fallback:
                logger.warning("No baseline ML model loaded and fallback disabled; skipping ML scoring")
                return []
            n = len(sample)
            train_size = max(10, int(n * 0.8))
            model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            X_train = self._transform_features(X[:train_size]) if self.scaler else X[:train_size]
            model.fit(X_train)
            scores = model.decision_function(self._transform_features(X) if self.scaler else X)
        else:
            if self.scaler is None:
                logger.warning("Baseline model loaded without scaler; scoring with raw features")
            X_scaled = self._transform_features(X)
            scores = self.model.decision_function(X_scaled)

        explanations = self._simple_explanations(features_df, scores)
        norm_scores = self.calibrator.normalize_array(scores)

        results = []
        for i, flow in enumerate(sample):
            norm_score = float(norm_scores[i])
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
        means = features_df[self.feature_names].mean()
        for _, row in features_df.iterrows():
            deviations = []
            for feat in self.feature_names:
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
