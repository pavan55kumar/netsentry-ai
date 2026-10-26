"""Local experiment registry and reproducibility tracker for NetSentry AI.

What it does:
    Maintains a persistent, local JSON catalog of all training experiments,
    recording dataset identifiers, model architectures, hyperparameters,
    validation scores, holdout metrics, and artifact paths.

Why it is needed:
    Academic research and cybersecurity compliance require auditable reproducibility.
    Tracking previous runs allows students to systematically compare feature selection
    experiments, algorithm changes, and tuning runs without relying on cloud services.

DCN / ML connection:
    Allows researchers to trace which feature combinations (e.g. adding TCP flags
    or inter-arrival times) delivered measurable gains in detection efficacy.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
import uuid


@dataclass
class ExperimentRecord:
    """Persistent snapshot of an individual training experiment."""
    run_id: str
    timestamp: str
    dataset_name: str
    rows_train: int
    rows_test: int
    features_count: int
    feature_names: list[str]
    split_strategy: str
    models_evaluated: list[str]
    champion_model: str
    selection_metric: str
    champion_metrics: dict[str, Any]
    all_models_summary: dict[str, Any]
    notes: list[str]
    artifacts_dir: str


class ExperimentTracker:
    """Manages reading and writing experiment records to local storage."""

    def __init__(self, storage_path: str | Path = "artifacts/experiments.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    def log_run(self, record: ExperimentRecord) -> None:
        """Append or update an experiment run in the registry."""
        runs = self.list_runs()
        runs.insert(0, asdict(record))
        # Keep recent 50 experiments
        runs = runs[:50]
        self.storage_path.write_text(json.dumps(runs, indent=2), encoding="utf-8")

    def list_runs(self) -> list[dict[str, Any]]:
        """Return all logged experiment records ordered from newest to oldest."""
        if not self.storage_path.is_file():
            return []
        try:
            return json.loads(self.storage_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Retrieve a specific experiment record by its run_id."""
        for run in self.list_runs():
            if run.get("run_id") == run_id:
                return run
        return None

    @staticmethod
    def create_run_id() -> str:
        """Generate a short, readable unique run identifier."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        short_uid = uuid.uuid4().hex[:6]
        return f"exp_{stamp}_{short_uid}"
