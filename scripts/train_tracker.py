#!/usr/bin/env python3
"""Interactive ML training pipeline with step-by-step continue prompts.

Train Isolation Forest on all-days BENIGN traffic, verify on labeled flows,
tune anomaly threshold, run benchmark, and print a final report.
"""

from __future__ import annotations

import json
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

from app.services.detection.features import FEATURE_NAMES, build_feature_matrix_from_cic, load_feature_schema, save_feature_schema
from app.services.detection.ml_engine import (
    ScoreCalibrator,
    compute_score_calibration,
    save_score_calibration,
)
from app.services.live.eve_parser import iter_eve_events, summarize_eve_event_types
from scripts.cic_loader import DEFAULT_PARQUET, FEATURE_COLUMNS, ensure_downloaded
from scripts.cic_preprocess import clean_cic_dataframe, filter_benign, is_attack_label
from scripts.evaluate_model import run_benchmark
from scripts.tune_threshold import run_threshold_tuning

ML_DIR = ROOT / "ml_models"
TRACKER_DIR = ML_DIR / "training_tracker"
DEFAULT_EVE = ROOT / "data" / "suricata" / "eve.json"

DATASET_PRESETS = {
    "1": ("100k", 100_000),
    "2": ("2M", 2_000_000),
}


@dataclass
class TrackerConfig:
    dataset_label: str
    max_train_rows: int
    csv_or_parquet_path: Path
    eve_json_path: Path
    contamination: float = 0.05
    n_estimators: int = 300
    # Rows per tree — small subsamples keep trees diverse; training on the
    # full dataset per tree is known to collapse recall on subtle attacks.
    max_samples: int = 4096
    random_state: int = 42


@dataclass
class PhaseResult:
    name: str
    status: str
    detail: str = ""
    metrics: dict = field(default_factory=dict)


def wait_for_continue(console: Console, step_title: str, description: str) -> str:
    """Block until the user types continue, skip, or quit."""
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


def load_flows_from_path(path: Path, progress: Progress, task_id) -> tuple[pd.DataFrame, dict]:
    """Load all CIC-style flows from parquet/csv (no per-day filter)."""
    meta: dict = {"source": str(path), "train_scope": "all_days_BENIGN"}

    if not path.exists():
        progress.update(task_id, description="Downloading CIC-IDS2017 via nids-datasets...")
        path = ensure_downloaded()
        meta["source"] = str(path)

    suffix = path.suffix.lower()
    progress.update(task_id, description=f"Reading {path.name}...")
    if suffix == ".csv":
        df = pd.read_csv(path, low_memory=False)
    elif suffix in {".parquet", ".pq"}:
        import pyarrow.parquet as pq

        available = pq.read_schema(path).names
        use_cols = [c for c in FEATURE_COLUMNS if c in available]
        df = pd.read_parquet(path, columns=use_cols, engine="pyarrow")
    else:
        raise ValueError(f"Unsupported dataset format: {suffix} (use .csv or .parquet)")

    progress.advance(task_id, 60)
    df = _normalize_label_column(df)
    meta["rows_loaded"] = len(df)
    progress.advance(task_id, 40)
    return df, meta


def subsample_benign(df: pd.DataFrame, max_rows: int, random_state: int) -> pd.DataFrame:
    benign = filter_benign(df)
    if len(benign) <= max_rows:
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


def evaluate_labeled(model, scaler, feature_names, df: pd.DataFrame, split_name: str) -> dict:
    X_df = build_feature_matrix_from_cic(df)
    mask = X_df[feature_names].notna().all(axis=1).to_numpy()
    df = df.iloc[mask].reset_index(drop=True)
    X = X_df.loc[mask, feature_names].values.astype(float)
    X_scaled = scaler.transform(X)

    label_col = "Label" if "Label" in df.columns else "attack_label"
    y_true = np.array([1 if is_attack_label(l) else 0 for l in df[label_col]])

    # Match runtime behavior: calibrated 0-10 score vs anomaly threshold.
    calibrator = ScoreCalibrator.load(ML_DIR / "score_calibration.json")
    norm_scores = calibrator.normalize_array(model.decision_function(X_scaled))
    y_pred = (norm_scores >= 5.0).astype(int)

    return {
        "split": split_name,
        "samples": len(y_true),
        "attacks": int(y_true.sum()),
        "benign": int((y_true == 0).sum()),
        "predicted_anomalies": int(y_pred.sum()),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }


def prompt_config(console: Console) -> TrackerConfig:
    console.print(
        Panel.fit(
            "[bold cyan]packetEye Model Training Pipeline[/]\n"
            "All-days BENIGN training with step-by-step continue prompts.\n"
            "Type [bold]continue[/] at each step to proceed toward the final report.",
            border_style="cyan",
        )
    )

    console.print("\n[bold]Training dataset size[/]")
    console.print("  [1] 100k rows — fast iteration / dev machines")
    console.print("  [2] 2M rows   — full baseline (matches production scale)")
    choice = Prompt.ask("Select size", choices=["1", "2"], default="1")
    label, max_rows = DATASET_PRESETS[choice]

    default_data = DEFAULT_PARQUET if DEFAULT_PARQUET.exists() else ROOT / "CIC-IDS2017" / "Network-Flows" / "CICIDS_Flow.parquet"
    csv_path_str = Prompt.ask(
        "CIC flows path (.csv or .parquet)",
        default=str(default_data),
    )
    eve_path_str = Prompt.ask("Suricata eve.json path (live monitor input)", default=str(DEFAULT_EVE))

    return TrackerConfig(
        dataset_label=label,
        max_train_rows=max_rows,
        csv_or_parquet_path=Path(csv_path_str).expanduser().resolve(),
        eve_json_path=Path(eve_path_str).expanduser().resolve(),
    )


def run_training_phase(config: TrackerConfig, console: Console) -> tuple[PhaseResult, object, object, list[str], dict]:
    load_meta: dict = {}
    train_rows = 0
    elapsed = 0.0

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
        flows, load_meta = load_flows_from_path(config.csv_or_parquet_path, progress, load_task)
        progress.update(load_task, completed=100)

        prep_task = progress.add_task("Preprocess BENIGN flows (all days)", total=100)
        progress.update(prep_task, advance=20)
        flows = subsample_benign(flows, config.max_train_rows, config.random_state)
        progress.update(prep_task, advance=30)
        cleaned = clean_cic_dataframe(flows)
        train_rows = len(cleaned)
        if train_rows < 100:
            return PhaseResult("training", "failed", f"Only {train_rows} rows after cleaning (need >= 100)"), None, None, [], load_meta
        progress.update(prep_task, advance=50)

        feat_task = progress.add_task("Build feature matrix", total=100)
        X_df = build_feature_matrix_from_cic(cleaned)
        X = X_df[FEATURE_NAMES].values.astype(float)
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
            f"Train IsolationForest ({train_rows:,} rows)",
            total=100,
        )
        started = time.perf_counter()
        model.fit(X_scaled)
        elapsed = time.perf_counter() - started
        progress.update(train_task, completed=100)

        save_task = progress.add_task("Save model artifacts", total=100)
        ML_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, ML_DIR / "isolation_forest_base.pkl")
        progress.update(save_task, advance=25)
        joblib.dump(scaler, ML_DIR / "feature_scaler.pkl")
        progress.update(save_task, advance=25)
        save_feature_schema(ML_DIR / "feature_schema.json")
        progress.update(save_task, advance=25)
        calibration = compute_score_calibration(model, X_scaled, random_state=config.random_state)
        save_score_calibration(calibration, ML_DIR / "score_calibration.json")
        progress.update(save_task, advance=25)

    feature_names = load_feature_schema(ML_DIR / "feature_schema.json")
    training_meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "CIC-IDS2017",
        "train_day": "all_days_BENIGN",
        "train_date": "mixed",
        "train_label": "BENIGN",
        "train_rows": train_rows,
        "train_target_rows": config.max_train_rows,
        "dataset_preset": config.dataset_label,
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

    detail = f"{train_rows:,} BENIGN rows (all days) in {elapsed:.1f}s"
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
        flows, load_meta = load_flows_from_path(config.csv_or_parquet_path, progress, load_task)
        verify_meta.update(load_meta)
        progress.update(load_task, completed=100)

        prep_task = progress.add_task("Clean and subsample labeled flows", total=100)
        cleaned = clean_cic_dataframe(flows)
        if len(cleaned) > config.max_train_rows:
            label_col = "Label"
            attacks = cleaned[cleaned[label_col].astype(str).str.upper() != "BENIGN"]
            benign = cleaned[cleaned[label_col].astype(str).str.upper() == "BENIGN"]
            attack_n = min(len(attacks), max(1000, config.max_train_rows // 5))
            benign_n = min(len(benign), config.max_train_rows - attack_n)
            parts = []
            if attack_n:
                parts.append(attacks.sample(n=attack_n, random_state=config.random_state))
            if benign_n:
                parts.append(benign.sample(n=benign_n, random_state=config.random_state))
            cleaned = pd.concat(parts, ignore_index=True) if parts else cleaned
        progress.update(prep_task, completed=100)

        eval_task = progress.add_task("Score labeled flows", total=100)
        metrics = evaluate_labeled(model, scaler, feature_names, cleaned, "all_days_labeled")
        progress.update(eval_task, completed=100)

    verify_meta["verify_metrics"] = metrics
    detail = (
        f"{metrics['samples']:,} samples | recall={metrics['recall']:.3f} "
        f"f1={metrics['f1']:.3f} | attacks={metrics['attacks']:,}"
    )
    status = "completed" if metrics["samples"] >= 50 else "warning"
    return PhaseResult("verification", status, detail, metrics), verify_meta


def run_threshold_phase(model, scaler, feature_names: list[str], console: Console) -> tuple[PhaseResult, dict]:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("Sweep anomaly thresholds (all days)", total=None)
        result = run_threshold_tuning(
            model=model,
            scaler=scaler,
            feature_names=feature_names,
            random_state=42,
        )
        progress.update(task_id, completed=100)

    rec = result.get("recommended", {})
    detail = (
        f"threshold={rec.get('threshold', '—')} | "
        f"attack recall={rec.get('attack_recall', 0):.3f} | "
        f"benign FP={rec.get('benign_fp_rate', 0):.3f}"
    )
    return PhaseResult("threshold_tuning", "completed", detail, rec), result


def run_benchmark_phase(model, scaler, feature_names: list[str], config: TrackerConfig, console: Console) -> tuple[PhaseResult, dict]:
    max_rows = min(config.max_train_rows, 100_000)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task(f"Benchmark on up to {max_rows:,} labeled rows", total=None)
        results = run_benchmark(
            model=model,
            scaler=scaler,
            feature_names=feature_names,
            max_eval_rows=max_rows,
            random_state=config.random_state,
        )
        progress.update(task_id, completed=100)

    overall = results.get("overall", {})
    detail = (
        f"{overall.get('samples', 0):,} samples | recall={overall.get('recall', 0):.3f} "
        f"f1={overall.get('f1', 0):.3f}"
    )
    return PhaseResult("benchmark", "completed", detail, overall), results


def render_input_summary(config: TrackerConfig, eve_summary: dict, load_meta: dict) -> Table:
    table = Table(title="Input Summary", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Input", style="cyan")
    table.add_column("Value")

    table.add_row("Dataset preset", config.dataset_label)
    table.add_row("Max train rows", f"{config.max_train_rows:,}")
    table.add_row("Training scope", "All days — BENIGN only")
    table.add_row("Verification scope", "All days — labeled flows")
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
    lines = [
        "[bold green]packetEye ML Training — Final Report[/]",
        "",
        f"Dataset preset: [cyan]{config.dataset_label}[/] ({config.max_train_rows:,} max train rows)",
        f"Training scope: [cyan]all days BENIGN[/]",
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
        lines.extend(
            [
                "",
                "[bold]Recommended anomaly threshold[/]",
                f"  ML_ANOMALY_THRESHOLD={rec.get('threshold', 5.0)}",
                f"  Attack recall (tuned sample): {rec.get('attack_recall', rec.get('tuesday_recall', 0)):.1%}",
                f"  Benign false-positive rate: {rec.get('benign_fp_rate', rec.get('monday_fp_rate', 0)):.1%}",
            ]
        )

    overall = (benchmark_data or {}).get("overall") if benchmark_data else None
    if overall:
        lines.extend(
            [
                "",
                "[bold]Benchmark (all-days labeled sample)[/]",
                f"  Accuracy:  {overall.get('accuracy', 0):.1%}",
                f"  Precision: {overall.get('precision', 0):.1%}",
                f"  Recall:    {overall.get('recall', 0):.1%}",
                f"  F1:        {overall.get('f1', 0):.1%}",
            ]
        )

    lines.extend(
        [
            "",
            "[bold]Saved artifacts[/]",
            f"  {ML_DIR / 'isolation_forest_base.pkl'}",
            f"  {ML_DIR / 'feature_scaler.pkl'}",
            f"  {ML_DIR / 'feature_schema.json'}",
            f"  {ML_DIR / 'training_metadata.json'}",
            f"  {ML_DIR / 'recommended_threshold.json'}",
            f"  {ML_DIR / 'benchmark_results.json'}",
            f"  {log_path}",
            "",
            "[bold]Next actions[/]",
            "  1. Set ML_ANOMALY_THRESHOLD in .env to the recommended value above",
            "  2. Run: python run.py  and upload a PCAP to test ML scoring",
            f"  3. Point live monitor at: SURICATA_EVE_PATH={config.eve_json_path}",
            "  4. Open /live in the packetEye dashboard for live NIDS",
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
    config = prompt_config(console)
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
        "Confirm dataset paths and preset above.\n"
        "The pipeline will train on [bold]all days BENIGN[/] traffic, then verify, tune threshold, and benchmark.",
    )
    if action == "quit":
        console.print("[yellow]Exited before training.[/]")
        return 0

    action = wait_for_continue(
        console,
        "Training",
        "Train Isolation Forest on all-days BENIGN flows and save model artifacts to ml_models/.",
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
        feature_names = load_feature_schema(ML_DIR / "feature_schema.json")

    action = wait_for_continue(
        console,
        "Verification",
        "Score a stratified all-days labeled sample and report accuracy, precision, recall, and F1.",
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
    )
    if action == "quit":
        log_path = save_run_log(config, phases, load_meta, verify_meta, eve_summary)
        console.print(f"[dim]Partial run log saved to {log_path}[/]")
        return 0
    if action == "continue":
        threshold_result, threshold_data = run_threshold_phase(model, scaler, feature_names, console)
        phases.append(threshold_result)
        console.print(f"\n[cyan]Threshold tuning:[/] {threshold_result.detail}\n")
    else:
        phases.append(PhaseResult("threshold_tuning", "skipped", "User skipped threshold tuning"))

    action = wait_for_continue(
        console,
        "Benchmark evaluation",
        "Run full benchmark on all-days labeled data and save benchmark_results.json.",
    )
    if action == "quit":
        log_path = save_run_log(config, phases, load_meta, verify_meta, eve_summary, threshold_data)
        console.print(f"[dim]Partial run log saved to {log_path}[/]")
        return 0
    if action == "continue":
        benchmark_result, benchmark_data = run_benchmark_phase(model, scaler, feature_names, config, console)
        phases.append(benchmark_result)
        console.print(f"\n[cyan]Benchmark:[/] {benchmark_result.detail}\n")
    else:
        phases.append(PhaseResult("benchmark", "skipped", "User skipped benchmark"))

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
