#!/usr/bin/env python3
"""Interactive ML training pipeline with step-by-step continue prompts.

Train Isolation Forest on all-days BENIGN traffic, tune anomaly threshold,
run benchmark, and print a final report — legacy (20) or full CIC (78) features.

Non-interactive (all steps):
  python scripts/train_tracker.py --feature-set full --yes
  python scripts/train_tracker.py --feature-set full --yes --write-env
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import MinMaxScaler

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.services.detection.features import (
    build_cic_matrix,
    feature_names_for,
    load_feature_schema_info,
    save_feature_fill_values,
    save_feature_schema,
)
from app.services.detection.ml_engine import (
    ScoreCalibrator,
    compute_score_calibration,
    save_score_calibration,
)
from app.services.live.eve_parser import iter_eve_events, summarize_eve_event_types
from scripts.cic_loader import (
    CIC_FULL_FEATURE_COLUMNS,
    DEFAULT_PARQUET,
    FEATURE_COLUMNS,
    ensure_downloaded,
    load_cic_flows,
)
from scripts.cic_preprocess import clean_cic_dataframe, filter_benign, is_attack_label
from scripts.evaluate_model import resolve_threshold, run_benchmark
from scripts.tune_threshold import run_threshold_tuning

ML_DIR = ROOT / "ml_models"
TRACKER_DIR = ML_DIR / "training_tracker"
DEFAULT_EVE = ROOT / "data" / "suricata" / "eve.json"
ENV_PATH = ROOT / ".env"

DATASET_PRESETS = {
    "1": ("100k", 100_000),
    "2": ("2M", 2_000_000),
    "3": ("all", None),
}


@dataclass
class TrackerConfig:
    dataset_label: str
    max_train_rows: int | None
    csv_or_parquet_path: Path
    eve_json_path: Path
    feature_set: str = "legacy"
    contamination: float = 0.08
    n_estimators: int = 300
    max_samples: int = 4096
    random_state: int = 42
    auto_continue: bool = False
    write_env: bool = False


@dataclass
class PhaseResult:
    name: str
    status: str
    detail: str = ""
    metrics: dict = field(default_factory=dict)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--feature-set",
        choices=["legacy", "full"],
        default=None,
        help="legacy = 20 features (v3); full = 78 CIC features (v4)",
    )
    parser.add_argument(
        "--dataset",
        choices=["100k", "2M", "all"],
        default=None,
        help="BENIGN training row cap (all = no subsampling, like train_baseline.py)",
    )
    parser.add_argument("--contamination", type=float, default=None)
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Run train → tune → benchmark without continue prompts",
    )
    parser.add_argument(
        "--write-env",
        action="store_true",
        help="After tuning, set ML_ANOMALY_THRESHOLD in .env to the recommended value",
    )
    parser.add_argument(
        "--flows-path",
        default=None,
        help="CIC parquet/csv path (default: CIC-IDS2017/Network-Flows/CICIDS_Flow.parquet)",
    )
    return parser.parse_args()


def wait_for_continue(console: Console, step_title: str, description: str, auto: bool = False) -> str:
    """Block until the user types continue, skip, or quit."""
    if auto:
        return "continue"
    console.print()
    console.print(
        Panel(
            description,
            title=f"[bold cyan]Next step: {step_title}[/]",
            border_style="cyan",
            padding=(1, 2),
        )
    )
    while True:
        answer = Prompt.ask(
            "Type [bold]continue[/] to run this step, [bold]skip[/] to skip, or [bold]quit[/] to exit",
            default="continue",
        ).strip().lower()
        if answer in {"continue", "c", ""}:
            return "continue"
        if answer == "skip":
            return "skip"
        if answer in {"quit", "q", "exit"}:
            return "quit"
        console.print("[yellow]Please enter continue, skip, or quit.[/]")


def _normalize_label_column(df: pd.DataFrame) -> pd.DataFrame:
    if "attack_label" in df.columns:
        df = df.copy()
        df["Label"] = df["attack_label"].astype(str).str.strip()
    elif "Label" not in df.columns:
        raise ValueError("Dataset must include Label or attack_label column")
    return df


def _parquet_columns_for(feature_set: str, path: Path) -> list[str]:
    import pyarrow.parquet as pq

    available = pq.read_schema(path).names
    wanted = CIC_FULL_FEATURE_COLUMNS if feature_set == "full" else FEATURE_COLUMNS
    return [c for c in wanted if c in available]


def load_flows_from_path(
    path: Path,
    feature_set: str,
    progress: Progress,
    task_id,
) -> tuple[pd.DataFrame, dict]:
    """Load all CIC-style flows from parquet/csv (no per-day filter)."""
    meta: dict = {"source": str(path), "train_scope": "all_days_BENIGN", "feature_set": feature_set}

    if not path.exists():
        progress.update(task_id, description="Downloading CIC-IDS2017 via nids-datasets...")
        path = ensure_downloaded()
        meta["source"] = str(path)

    if path.resolve() == DEFAULT_PARQUET.resolve() or (
        path.suffix.lower() in {".parquet", ".pq"} and path.name == DEFAULT_PARQUET.name
    ):
        progress.update(task_id, description=f"Reading {path.name} ({feature_set} columns)...")
        df = load_cic_flows(day=None, feature_set=feature_set)
        progress.advance(task_id, 100)
        meta["rows_loaded"] = len(df)
        return df, meta

    suffix = path.suffix.lower()
    progress.update(task_id, description=f"Reading {path.name}...")
    if suffix == ".csv":
        df = pd.read_csv(path, low_memory=False)
    elif suffix in {".parquet", ".pq"}:
        use_cols = _parquet_columns_for(feature_set, path)
        df = pd.read_parquet(path, columns=use_cols, engine="pyarrow")
    else:
        raise ValueError(f"Unsupported dataset format: {suffix} (use .csv or .parquet)")

    progress.advance(task_id, 60)
    df = _normalize_label_column(df)
    meta["rows_loaded"] = len(df)
    progress.advance(task_id, 40)
    return df, meta


def subsample_benign(df: pd.DataFrame, max_rows: int | None, random_state: int) -> pd.DataFrame:
    benign = filter_benign(df)
    if max_rows is None or len(benign) <= max_rows:
        return benign
    return benign.sample(n=max_rows, random_state=random_state).reset_index(drop=True)


def summarize_eve_json(path: Path) -> dict:
    summary = {
        "path": str(path),
        "exists": path.is_file(),
        "size_bytes": 0,
        "flow_events": 0,
        "alert_events": 0,
        "other_events": 0,
        "last_modified": None,
    }
    if not path.is_file():
        return summary

    stat = path.stat()
    summary["size_bytes"] = stat.st_size
    summary["last_modified"] = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

    try:
        counts = summarize_eve_event_types(iter_eve_events(path))
        summary.update(counts)
    except OSError as exc:
        summary["error"] = str(exc)

    return summary


def evaluate_labeled(
    model,
    scaler,
    feature_names: list[str],
    df: pd.DataFrame,
    split_name: str,
    feature_set: str,
    threshold: float | None = None,
) -> dict:
    X_df = build_cic_matrix(df, feature_set)
    mask = X_df[feature_names].notna().all(axis=1).to_numpy()
    df = df.iloc[mask].reset_index(drop=True)
    X = X_df.loc[mask, feature_names].values.astype(float)
    X_scaled = scaler.transform(X)

    label_col = "Label" if "Label" in df.columns else "attack_label"
    y_true = np.array([1 if is_attack_label(l) else 0 for l in df[label_col]])

    calibrator = ScoreCalibrator.load(ML_DIR / "score_calibration.json")
    if threshold is None:
        threshold = resolve_threshold()
    norm_scores = calibrator.normalize_array(model.decision_function(X_scaled))
    y_pred = (norm_scores >= threshold).astype(int)

    return {
        "split": split_name,
        "threshold": float(threshold),
        "samples": len(y_true),
        "attacks": int(y_true.sum()),
        "benign": int((y_true == 0).sum()),
        "predicted_anomalies": int(y_pred.sum()),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }


def prompt_config(console: Console, cli: argparse.Namespace | None = None) -> TrackerConfig:
    cli = cli or argparse.Namespace()
    console.print(
        Panel.fit(
            "[bold cyan]packetEye Model Training Pipeline[/]\n"
            "Train → tune threshold → benchmark → final report\n"
            "Supports [bold]legacy[/] (20 features) and [bold]full[/] (78 CIC features).\n"
            "Type [bold]continue[/] at each step, or pass [bold]--yes[/] to run all steps.",
            border_style="cyan",
        )
    )

    if cli.feature_set:
        feature_set = cli.feature_set
    else:
        console.print("\n[bold]Feature set[/]")
        console.print("  [1] legacy — 20 engineered features (schema v3)")
        console.print("  [2] full   — 78 CIC-IDS2017 features (schema v4, recommended)")
        fs_choice = Prompt.ask("Select feature set", choices=["1", "2"], default="2")
        feature_set = "full" if fs_choice == "2" else "legacy"

    if cli.dataset:
        label_to_preset = {"100k": "1", "2M": "2", "all": "3"}
        choice = label_to_preset[cli.dataset]
    else:
        console.print("\n[bold]Training dataset size (BENIGN rows)[/]")
        console.print("  [1] 100k rows — fast iteration")
        console.print("  [2] 2M rows   — production-scale sample")
        console.print("  [3] all rows  — full BENIGN set (matches train_baseline.py)")
        choice = Prompt.ask("Select size", choices=["1", "2", "3"], default="3" if feature_set == "full" else "2")
    label, max_rows = DATASET_PRESETS[choice]

    default_data = DEFAULT_PARQUET if DEFAULT_PARQUET.exists() else ROOT / "CIC-IDS2017" / "Network-Flows" / "CICIDS_Flow.parquet"
    if cli.flows_path:
        csv_path_str = cli.flows_path
    else:
        csv_path_str = Prompt.ask(
            "CIC flows path (.csv or .parquet)",
            default=str(default_data),
        )
    eve_path_str = Prompt.ask("Suricata eve.json path (live monitor input)", default=str(DEFAULT_EVE))

    contamination = cli.contamination if cli.contamination is not None else (
        0.08 if feature_set == "full" else 0.05
    )

    return TrackerConfig(
        dataset_label=label,
        max_train_rows=max_rows,
        csv_or_parquet_path=Path(csv_path_str).expanduser().resolve(),
        eve_json_path=Path(eve_path_str).expanduser().resolve(),
        feature_set=feature_set,
        contamination=contamination,
        auto_continue=bool(cli.yes),
        write_env=bool(cli.write_env),
    )


def run_training_phase(config: TrackerConfig, console: Console) -> tuple[PhaseResult, object, object, list[str], dict]:
    load_meta: dict = {}
    train_rows = 0
    elapsed = 0.0
    feature_set = config.feature_set
    feature_names = feature_names_for(feature_set)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        load_task = progress.add_task("Load all-days training data", total=100)
        flows, load_meta = load_flows_from_path(
            config.csv_or_parquet_path, feature_set, progress, load_task
        )
        progress.update(load_task, completed=100)

        prep_task = progress.add_task("Preprocess BENIGN flows (all days)", total=100)
        progress.update(prep_task, advance=20)
        flows = subsample_benign(flows, config.max_train_rows, config.random_state)
        progress.update(prep_task, advance=30)
        cleaned = clean_cic_dataframe(flows, feature_set=feature_set)
        train_rows = len(cleaned)
        if train_rows < 100:
            return (
                PhaseResult("training", "failed", f"Only {train_rows} rows after cleaning (need >= 100)"),
                None,
                None,
                [],
                load_meta,
            )
        progress.update(prep_task, advance=50)

        feat_task = progress.add_task(f"Build {len(feature_names)}-feature matrix", total=100)
        X_df = build_cic_matrix(cleaned, feature_set)
        X = X_df[feature_names].values.astype(float)
        progress.update(feat_task, completed=100)

        scale_task = progress.add_task("Fit MinMaxScaler", total=100)
        scaler = MinMaxScaler()
        X_scaled = scaler.fit_transform(X)
        progress.update(scale_task, completed=100)

        model = IsolationForest(
            n_estimators=config.n_estimators,
            contamination=config.contamination,
            max_samples=min(config.max_samples, train_rows),
            random_state=config.random_state,
            n_jobs=-1,
        )
        train_task = progress.add_task(
            f"Train IsolationForest ({train_rows:,} rows, {feature_set})",
            total=100,
        )
        started = time.perf_counter()
        model.fit(X_scaled)
        elapsed = time.perf_counter() - started
        progress.update(train_task, completed=100)

        save_task = progress.add_task("Save model artifacts", total=100)
        ML_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, ML_DIR / "isolation_forest_base.pkl")
        progress.update(save_task, advance=20)
        joblib.dump(scaler, ML_DIR / "feature_scaler.pkl")
        progress.update(save_task, advance=20)
        save_feature_schema(ML_DIR / "feature_schema.json", feature_set=feature_set)
        progress.update(save_task, advance=20)
        calibration = compute_score_calibration(model, X_scaled, random_state=config.random_state)
        save_score_calibration(calibration, ML_DIR / "score_calibration.json")
        progress.update(save_task, advance=20)
        if feature_set == "full":
            medians = np.median(X, axis=0)
            fill_values = {name: float(medians[i]) for i, name in enumerate(feature_names)}
            save_feature_fill_values(fill_values, ML_DIR / "feature_fill_values.json")
        progress.update(save_task, advance=20)

    feature_names = load_feature_schema_info(ML_DIR / "feature_schema.json")["feature_names"]
    training_meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "CIC-IDS2017",
        "train_day": "all_days_BENIGN",
        "train_date": "mixed",
        "train_label": "BENIGN",
        "train_rows": train_rows,
        "train_target_rows": config.max_train_rows,
        "dataset_preset": config.dataset_label,
        "feature_set": feature_set,
        "feature_count": len(feature_names),
        "contamination": config.contamination,
        "n_estimators": config.n_estimators,
        "max_samples": min(config.max_samples, train_rows),
        "training_seconds": round(elapsed, 2),
        "data_source": load_meta.get("source"),
        "eve_json_path": str(config.eve_json_path),
    }
    with open(ML_DIR / "training_metadata.json", "w", encoding="utf-8") as f:
        json.dump(training_meta, f, indent=2)

    detail = f"{train_rows:,} BENIGN rows ({feature_set}, {len(feature_names)} features) in {elapsed:.1f}s"
    return (
        PhaseResult("training", "completed", detail, {"train_rows": train_rows, "seconds": round(elapsed, 2)}),
        model,
        scaler,
        feature_names,
        {**load_meta, **training_meta},
    )


def run_verify_phase(
    config: TrackerConfig,
    model,
    scaler,
    feature_names: list[str],
    console: Console,
) -> tuple[PhaseResult, dict]:
    verify_meta: dict = {}
    feature_set = config.feature_set
    eval_cap = config.max_train_rows if config.max_train_rows else 100_000

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        load_task = progress.add_task("Load all-days labeled verification set", total=100)
        flows, load_meta = load_flows_from_path(
            config.csv_or_parquet_path, feature_set, progress, load_task
        )
        verify_meta.update(load_meta)
        progress.update(load_task, completed=100)

        prep_task = progress.add_task("Clean and subsample labeled flows", total=100)
        cleaned = clean_cic_dataframe(flows, feature_set=feature_set)
        if len(cleaned) > eval_cap:
            label_col = "Label"
            attacks = cleaned[cleaned[label_col].astype(str).str.upper() != "BENIGN"]
            benign = cleaned[cleaned[label_col].astype(str).str.upper() == "BENIGN"]
            attack_n = min(len(attacks), max(1000, eval_cap // 5))
            benign_n = min(len(benign), eval_cap - attack_n)
            parts = []
            if attack_n:
                parts.append(attacks.sample(n=attack_n, random_state=config.random_state))
            if benign_n:
                parts.append(benign.sample(n=benign_n, random_state=config.random_state))
            cleaned = pd.concat(parts, ignore_index=True) if parts else cleaned
        progress.update(prep_task, completed=100)

        eval_task = progress.add_task("Score labeled flows (pre-tune threshold 5.0)", total=100)
        metrics = evaluate_labeled(
            model, scaler, feature_names, cleaned, "all_days_labeled", feature_set, threshold=5.0
        )
        progress.update(eval_task, completed=100)

    verify_meta["verify_metrics"] = metrics
    detail = (
        f"{metrics['samples']:,} samples | recall={metrics['recall']:.3f} "
        f"f1={metrics['f1']:.3f} | attacks={metrics['attacks']:,} @ threshold 5.0"
    )
    status = "completed" if metrics["samples"] >= 50 else "warning"
    return PhaseResult("verification", status, detail, metrics), verify_meta


def run_threshold_phase(
    config: TrackerConfig,
    model,
    scaler,
    feature_names: list[str],
    console: Console,
) -> tuple[PhaseResult, dict]:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task(
            f"Sweep anomaly thresholds ({config.feature_set})", total=None
        )
        result = run_threshold_tuning(
            model=model,
            scaler=scaler,
            feature_names=feature_names,
            random_state=config.random_state,
            feature_set=config.feature_set,
        )
        progress.update(task_id, completed=100)

    rec = result.get("recommended", {})
    detail = (
        f"threshold={rec.get('threshold', '—')} | "
        f"recall={rec.get('recall', rec.get('attack_recall', 0)):.3f} | "
        f"f1={rec.get('f1', 0):.3f} | "
        f"benign FP={rec.get('benign_fp_rate', 0):.3f}"
    )
    return PhaseResult("threshold_tuning", "completed", detail, rec), result


def run_benchmark_phase(
    config: TrackerConfig,
    model,
    scaler,
    feature_names: list[str],
    console: Console,
) -> tuple[PhaseResult, dict]:
    max_rows = min(config.max_train_rows or 100_000, 100_000)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task(
            f"Benchmark ({config.feature_set}, up to {max_rows:,} rows)", total=None
        )
        results = run_benchmark(
            model=model,
            scaler=scaler,
            feature_names=feature_names,
            max_eval_rows=max_rows,
            random_state=config.random_state,
            feature_set=config.feature_set,
        )
        progress.update(task_id, completed=100)

    overall = results.get("overall", {})
    by_label = results.get("by_attack_label") or {}
    portscan = (by_label.get("PortScan") or {}).get("recall")
    detail = (
        f"{overall.get('samples', 0):,} samples | recall={overall.get('recall', 0):.3f} "
        f"f1={overall.get('f1', 0):.3f}"
    )
    if portscan is not None:
        detail += f" | PortScan recall={portscan:.3f}"
    return PhaseResult("benchmark", "completed", detail, overall), results


def write_env_threshold(threshold: float, console: Console) -> PhaseResult:
    if not ENV_PATH.is_file():
        return PhaseResult("apply_env", "skipped", f"{ENV_PATH} not found — set ML_ANOMALY_THRESHOLD={threshold} manually")
    text = ENV_PATH.read_text(encoding="utf-8")
    line = f"ML_ANOMALY_THRESHOLD={threshold}"
    if re.search(r"^ML_ANOMALY_THRESHOLD=", text, flags=re.MULTILINE):
        text = re.sub(r"^ML_ANOMALY_THRESHOLD=.*$", line, text, count=1, flags=re.MULTILINE)
    else:
        text = text.rstrip() + f"\n{line}\n"
    ENV_PATH.write_text(text, encoding="utf-8")
    return PhaseResult("apply_env", "completed", f"Updated {ENV_PATH.name}: {line}")


def render_input_summary(config: TrackerConfig, eve_summary: dict, load_meta: dict) -> Table:
    table = Table(title="Input Summary", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Input", style="cyan")
    table.add_column("Value")

    rows_label = "all BENIGN" if config.max_train_rows is None else f"{config.max_train_rows:,}"
    table.add_row("Feature set", f"{config.feature_set} ({len(feature_names_for(config.feature_set))} features)")
    table.add_row("Dataset preset", config.dataset_label)
    table.add_row("Max train rows", rows_label)
    table.add_row("Contamination", str(config.contamination))
    table.add_row("Training scope", "All days — BENIGN only")
    table.add_row("Flows file", str(config.csv_or_parquet_path))
    table.add_row("Flows exists", "yes" if config.csv_or_parquet_path.exists() else "no (will download)")
    table.add_row("Rows loaded", str(load_meta.get("rows_loaded", "—")))
    table.add_row("eve.json", str(config.eve_json_path))
    table.add_row("eve.json exists", "yes" if eve_summary["exists"] else "no")
    if eve_summary["exists"]:
        table.add_row("eve.json size", f"{eve_summary['size_bytes']:,} bytes")
        table.add_row("eve flow events", f"{eve_summary['flow_events']:,}")
        table.add_row("eve alert events", f"{eve_summary['alert_events']:,}")
    return table


def render_phase_summary(phases: list[PhaseResult]) -> Table:
    table = Table(title="Run Phases", box=box.ROUNDED)
    table.add_column("Phase", style="cyan")
    table.add_column("Status")
    table.add_column("Detail")

    status_style = {"completed": "green", "warning": "yellow", "failed": "red", "skipped": "dim", "pending": "dim"}
    for phase in phases:
        style = status_style.get(phase.status, "white")
        table.add_row(phase.name, Text(phase.status, style=style), phase.detail)
    return table


def render_final_report(
    config: TrackerConfig,
    phases: list[PhaseResult],
    threshold_data: dict | None,
    benchmark_data: dict | None,
    log_path: Path,
) -> Panel:
    feature_count = len(feature_names_for(config.feature_set))
    lines = [
        "[bold green]packetEye ML Training — Final Report[/]",
        "",
        f"Feature set: [cyan]{config.feature_set}[/] ({feature_count} features)",
        f"Dataset preset: [cyan]{config.dataset_label}[/]",
        "",
        "[bold]Phase results[/]",
    ]

    for phase in phases:
        icon = {"completed": "[green]✓[/]", "skipped": "[dim]−[/]", "failed": "[red]✗[/]", "warning": "[yellow]![/]"}.get(
            phase.status, "·"
        )
        lines.append(f"  {icon} {phase.name}: {phase.detail}")

    rec = (threshold_data or {}).get("recommended") if threshold_data else None
    if rec:
        th = rec.get("threshold", 5.0)
        lines.extend(
            [
                "",
                "[bold]Recommended anomaly threshold[/] (calibrated 0–10 scale)",
                f"  ML_ANOMALY_THRESHOLD={th}",
                f"  Attack recall (tune sample): {rec.get('recall', rec.get('attack_recall', 0)):.1%}",
                f"  F1 (tune sample): {rec.get('f1', 0):.1%}",
                f"  Benign false-positive rate: {rec.get('benign_fp_rate', 0):.1%}",
            ]
        )

    overall = (benchmark_data or {}).get("overall") if benchmark_data else None
    by_label = (benchmark_data or {}).get("by_attack_label") if benchmark_data else None
    if overall:
        lines.extend(
            [
                "",
                "[bold]Benchmark (all-days labeled sample)[/]",
                f"  Threshold: {overall.get('threshold', resolve_threshold())}",
                f"  Accuracy:  {overall.get('accuracy', 0):.1%}",
                f"  Precision: {overall.get('precision', 0):.1%}",
                f"  Recall:    {overall.get('recall', 0):.1%}",
                f"  F1:        {overall.get('f1', 0):.1%}",
            ]
        )
    if by_label:
        lines.append("")
        lines.append("[bold]Key attack recalls[/]")
        for label in ("PortScan", "SSH-Patator", "FTP-Patator", "Bot", "DDoS"):
            entry = by_label.get(label)
            if entry:
                lines.append(f"  {label}: {entry.get('recall', 0):.1%}")

    artifact_lines = [
        f"  {ML_DIR / 'isolation_forest_base.pkl'}",
        f"  {ML_DIR / 'feature_scaler.pkl'}",
        f"  {ML_DIR / 'feature_schema.json'}",
        f"  {ML_DIR / 'score_calibration.json'}",
        f"  {ML_DIR / 'training_metadata.json'}",
        f"  {ML_DIR / 'recommended_threshold.json'}",
        f"  {ML_DIR / 'benchmark_results.json'}",
    ]
    if config.feature_set == "full":
        artifact_lines.append(f"  {ML_DIR / 'feature_fill_values.json'}")

    lines.extend(
        [
            "",
            "[bold]Saved artifacts[/]",
            *artifact_lines,
            f"  {log_path}",
            "",
            "[bold]Next actions[/]",
            "  1. Set ML_ANOMALY_THRESHOLD in .env (or use --write-env next run)",
            "  2. Restart packetEye so the live monitor loads the new model",
            "  3. Start capture + ML live monitor and test (e.g. nmap -sS lab target)",
            f"  4. Point live monitor at: SURICATA_EVE_PATH={config.eve_json_path}",
        ]
    )

    return Panel("\n".join(lines), title="Final Report", border_style="green", padding=(1, 2))


def save_run_log(
    config: TrackerConfig,
    phases: list[PhaseResult],
    load_meta: dict,
    verify_meta: dict,
    eve_summary: dict,
    threshold_data: dict | None = None,
    benchmark_data: dict | None = None,
) -> Path:
    TRACKER_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload = {
        "run_id": stamp,
        "config": {
            **asdict(config),
            "csv_or_parquet_path": str(config.csv_or_parquet_path),
            "eve_json_path": str(config.eve_json_path),
            "train_scope": "all_days_BENIGN",
            "verify_scope": "all_days_labeled",
        },
        "phases": [asdict(p) for p in phases],
        "load_meta": load_meta,
        "verify_meta": verify_meta,
        "threshold": threshold_data,
        "benchmark": {
            "overall": (benchmark_data or {}).get("overall"),
            "by_attack_label": {
                k: {"recall": v.get("recall"), "f1": v.get("f1")}
                for k, v in ((benchmark_data or {}).get("by_attack_label") or {}).items()
            },
            "summary": (benchmark_data or {}).get("summary"),
        },
        "eve_summary": eve_summary,
    }
    run_path = TRACKER_DIR / f"run_{stamp}.json"
    with open(run_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    latest = TRACKER_DIR / "latest_run.json"
    with open(latest, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return run_path


def main() -> int:
    console = Console()
    cli = parse_args()
    config = prompt_config(console, cli)
    auto = config.auto_continue
    eve_summary = summarize_eve_json(config.eve_json_path)
    phases: list[PhaseResult] = []
    load_meta: dict = {}
    verify_meta: dict = {}
    threshold_data: dict | None = None
    benchmark_data: dict | None = None
    model = scaler = None
    feature_names: list[str] = []

    console.print()
    console.print(render_input_summary(config, eve_summary, {}))
    action = wait_for_continue(
        console,
        "Review inputs",
        "Confirm dataset paths, feature set, and preset above.\n"
        "Pipeline: [bold]train → verify → tune threshold → benchmark → apply .env[/]",
        auto=auto,
    )
    if action == "quit":
        console.print("[yellow]Exited before training.[/]")
        return 0

    action = wait_for_continue(
        console,
        "Training",
        f"Train Isolation Forest on all-days BENIGN ({config.feature_set}, "
        f"{len(feature_names_for(config.feature_set))} features) and save ml_models/.",
        auto=auto,
    )
    if action == "quit":
        return 0
    if action == "continue":
        train_result, model, scaler, feature_names, load_meta = run_training_phase(config, console)
        phases.append(train_result)
        if train_result.status == "failed":
            console.print(Panel(f"[red]Training failed:[/] {train_result.detail}", border_style="red"))
            save_run_log(config, phases, load_meta, {}, eve_summary)
            return 1
        console.print(f"\n[green]Training complete.[/] {train_result.detail}\n")
    else:
        phases.append(PhaseResult("training", "skipped", "User skipped training"))
        if not (ML_DIR / "isolation_forest_base.pkl").exists():
            console.print("[red]Cannot continue without a trained model. Run training first.[/]")
            return 1
        model = joblib.load(ML_DIR / "isolation_forest_base.pkl")
        scaler = joblib.load(ML_DIR / "feature_scaler.pkl")
        info = load_feature_schema_info(ML_DIR / "feature_schema.json")
        feature_names = info["feature_names"]
        config.feature_set = info["feature_set"]

    action = wait_for_continue(
        console,
        "Verification",
        "Quick labeled check at threshold 5.0 (full tuning happens in the next step).",
        auto=auto,
    )
    if action == "quit":
        log_path = save_run_log(config, phases, load_meta, verify_meta, eve_summary)
        console.print(f"[dim]Partial run log saved to {log_path}[/]")
        return 0
    if action == "continue":
        verify_result, verify_meta = run_verify_phase(config, model, scaler, feature_names, console)
        phases.append(verify_result)
        console.print(f"\n[cyan]Verification:[/] {verify_result.detail}\n")
    else:
        phases.append(PhaseResult("verification", "skipped", "User skipped verification"))

    action = wait_for_continue(
        console,
        "Threshold tuning",
        "Sweep ML_ANOMALY_THRESHOLD values and write recommended_threshold.json.",
        auto=auto,
    )
    if action == "quit":
        log_path = save_run_log(config, phases, load_meta, verify_meta, eve_summary)
        console.print(f"[dim]Partial run log saved to {log_path}[/]")
        return 0
    if action == "continue":
        threshold_result, threshold_data = run_threshold_phase(config, model, scaler, feature_names, console)
        phases.append(threshold_result)
        console.print(f"\n[cyan]Threshold tuning:[/] {threshold_result.detail}\n")
    else:
        phases.append(PhaseResult("threshold_tuning", "skipped", "User skipped threshold tuning"))

    action = wait_for_continue(
        console,
        "Benchmark evaluation",
        "Run full benchmark on all-days labeled data and save benchmark_results.json.",
        auto=auto,
    )
    if action == "quit":
        log_path = save_run_log(config, phases, load_meta, verify_meta, eve_summary, threshold_data)
        console.print(f"[dim]Partial run log saved to {log_path}[/]")
        return 0
    if action == "continue":
        benchmark_result, benchmark_data = run_benchmark_phase(config, model, scaler, feature_names, console)
        phases.append(benchmark_result)
        console.print(f"\n[cyan]Benchmark:[/] {benchmark_result.detail}\n")
    else:
        phases.append(PhaseResult("benchmark", "skipped", "User skipped benchmark"))

    rec = (threshold_data or {}).get("recommended") if threshold_data else None
    if rec:
        should_write = config.write_env
        if not should_write and not auto:
            should_write = wait_for_continue(
                console,
                "Apply threshold to .env",
                f"Write ML_ANOMALY_THRESHOLD={rec.get('threshold')} to {ENV_PATH.name}?",
            ) == "continue"
        if should_write:
            env_result = write_env_threshold(float(rec["threshold"]), console)
            phases.append(env_result)
            console.print(f"\n[cyan]{env_result.detail}[/]\n")
        elif auto:
            phases.append(
                PhaseResult(
                    "apply_env",
                    "skipped",
                    f"Pass --write-env to set ML_ANOMALY_THRESHOLD={rec.get('threshold')} in .env",
                )
            )

    console.print(render_phase_summary(phases))
    console.print()
    console.print(render_input_summary(config, eve_summary, load_meta))
    console.print()

    log_path = save_run_log(config, phases, load_meta, verify_meta, eve_summary, threshold_data, benchmark_data)
    console.print(render_final_report(config, phases, threshold_data, benchmark_data, log_path))
    console.print(f"\n[dim]Run log saved to {log_path}[/]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())