"""Data generation, validation, and leakage-aware preparation."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import numpy as np
import pandas as pd
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split

DEMO_FEATURES = ["flow_duration_ms", "total_fwd_packets", "total_backward_packets", "flow_bytes_per_second", "flow_packets_per_second", "syn_flag_count", "rst_flag_count", "average_packet_size"]

@dataclass
class PreparedData:
    X_train: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series
    y_test: pd.Series
    feature_names: list[str]
    notes: list[str]

def make_demo_dataset(rows: int = 1200, random_state: int = 42) -> pd.DataFrame:
    """Create synthetic flows only for a runnable demo, never for real-world claims."""
    X, y = make_classification(n_samples=rows, n_features=len(DEMO_FEATURES), n_informative=6, n_redundant=1, weights=[0.72, 0.28], class_sep=1.0, flip_y=0.04, random_state=random_state)
    frame = pd.DataFrame(X, columns=DEMO_FEATURES)
    for column in ["flow_duration_ms", "total_fwd_packets", "total_backward_packets", "flow_bytes_per_second", "flow_packets_per_second", "average_packet_size"]:
        frame[column] = np.abs(frame[column] * 100).round(3)
    frame["syn_flag_count"] = np.clip(np.rint(frame["syn_flag_count"] + 2), 0, None)
    frame["rst_flag_count"] = np.clip(np.rint(frame["rst_flag_count"] + 1), 0, None)
    frame["label"] = np.where(y == 1, "malicious", "benign")
    return frame

def load_csv(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {path}")
    return pd.read_csv(path, low_memory=False)

def _binary_target(series: pd.Series, positive_label: str | None) -> pd.Series:
    cleaned = series.astype(str).str.strip()
    distinct = sorted(cleaned.dropna().unique())
    if len(distinct) != 2:
        raise ValueError(f"This baseline needs exactly two target values; found {distinct}. Filter/map labels to benign versus malicious first.")
    if positive_label is None:
        likely = [v for v in distinct if v.lower() not in {"benign", "normal", "0", "false"}]
        positive_label = likely[0] if len(likely) == 1 else distinct[1]
    if positive_label not in distinct:
        raise ValueError(f"--positive-label {positive_label!r} is not one of {distinct}")
    return (cleaned == positive_label).astype(int)

def prepare_data(frame: pd.DataFrame, label_column: str, test_size: float = 0.25, random_state: int = 42, positive_label: str | None = None, extra_drop_columns: Iterable[str] = ()) -> PreparedData:
    """Validate flow data then make a stratified, exact-duplicate-safe holdout split."""
    if not 0 < test_size < 0.5:
        raise ValueError("test_size must be greater than 0 and less than 0.5")
    data = frame.copy(); data.columns = [str(c).strip() for c in data.columns]
    if label_column not in data.columns:
        raise ValueError(f"Label column {label_column!r} is absent. Available columns: {list(data.columns)}")
    data = data.dropna(subset=[label_column]).reset_index(drop=True)
    y = _binary_target(data[label_column], positive_label); notes: list[str] = []
    words = ("label", "target", "attack", "class", "category", "outcome")
    requested = {c.strip() for c in extra_drop_columns}
    automatic = {c for c in data.columns if c != label_column and any(word in c.lower() for word in words)}
    candidate = data.drop(columns=[c for c in requested | automatic | {label_column} if c in data], errors="ignore")
    numeric = candidate.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
    ignored = sorted(set(candidate.columns) - set(numeric.columns))
    if ignored: notes.append("Ignored non-numeric columns: " + ", ".join(ignored))
    if automatic: notes.append("Dropped possible target/leakage columns: " + ", ".join(sorted(automatic)))
    if requested - set(data.columns): notes.append("Requested drop columns not found: " + ", ".join(sorted(requested - set(data.columns))))
    if numeric.shape[1] == 0:
        raise ValueError("No numeric feature columns remain. Convert appropriate flow measurements to numbers.")
    combined = numeric.copy(); combined["__target__"] = y.to_numpy(); before = len(combined)
    combined = combined.drop_duplicates(subset=list(numeric.columns), keep="first")
    if len(combined) < before: notes.append(f"Removed {before - len(combined)} exact duplicate feature rows before splitting.")
    X = combined.drop(columns="__target__"); y = combined["__target__"].astype(int)
    if y.value_counts().min() < 2:
        raise ValueError("Each class needs at least two rows after validation/deduplication.")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state, stratify=y)
    notes += [f"Used a fixed, stratified holdout split (random_state={random_state}).", "For time-ordered or host-overlap data, replace this with a time/group split before trusting results."]
    return PreparedData(X_train, X_test, y_train, y_test, list(X.columns), notes)
