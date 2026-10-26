"""Leakage-aware data preparation and preprocessing pipeline for NetSentry AI.

What it does:
    Cleans raw flow data, detects and removes target leakage columns, handles
    duplicate records according to explicit research policies, safely manages
    infinite and missing values, and creates un-leaked train/test partitions.

Why it is needed:
    Data leakage is the #1 cause of artificially inflated ML metrics in cybersecurity.
    If target indicators, session IDs, or exact test records contaminate training data,
    the model will fail catastrophically when deployed against live network traffic.

DCN / ML connection:
    Flow records from network taps often contain duplicate retransmissions or repeated
    keep-alives. Deduplication must be conscious of whether duplicate records reflect
    benign baseline volume or harmful evaluation leakage.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable
import numpy as np
import pandas as pd

from .splitting import split_dataset, SplitStrategy


class DeduplicationPolicy(str, Enum):
    REMOVE_EXACT = "remove_exact"
    KEEP_ALL = "keep_all"


@dataclass
class PreparedData:
    """Container for cleanly partitioned and validated datasets."""
    X_train: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series
    y_test: pd.Series
    feature_names: list[str]
    notes: list[str] = field(default_factory=list)
    label_mapping: dict[str, int] = field(default_factory=dict)
    target_names: list[str] = field(default_factory=list)
    is_multiclass: bool = False


LEAKAGE_KEYWORDS = (
    "label",
    "target",
    "attack",
    "class",
    "category",
    "outcome",
    "flow id",
    "flow_id",
    "timestamp",
    "time_stamp",
    "src ip",
    "src_ip",
    "source ip",
    "source_ip",
    "dst ip",
    "dst_ip",
    "destination ip",
    "destination_ip",
)


def detect_target_leakage(columns: list[str], label_column: str) -> list[str]:
    """Detect columns that likely encode the target or direct identifiers."""
    leaky = []
    lbl_lower = label_column.lower().strip()
    for col in columns:
        c_lower = col.lower().strip()
        if c_lower == lbl_lower:
            continue
        if any(keyword in c_lower for keyword in LEAKAGE_KEYWORDS):
            leaky.append(col)
    return leaky


def _encode_target(
    series: pd.Series, positive_label: str | None = None, multiclass: bool = False
) -> tuple[pd.Series, dict[str, int], list[str]]:
    """Clean and encode targets for binary or multi-class learning."""
    cleaned = series.astype(str).str.strip()
    distinct = sorted(cleaned.dropna().unique())

    if len(distinct) < 2:
        raise ValueError(f"Target column must contain at least 2 distinct classes. Found: {distinct}")

    if not multiclass:
        # Binary target mode
        if len(distinct) == 2:
            if positive_label is None:
                likely = [v for v in distinct if v.lower() not in {"benign", "normal", "0", "false"}]
                pos = likely[0] if len(likely) == 1 else distinct[1]
            else:
                pos = positive_label
            if pos not in distinct:
                raise ValueError(f"--positive-label {pos!r} is not one of {distinct}")
            neg = [v for v in distinct if v != pos][0]
            label_map = {neg: 0, pos: 1}
            target_names = [neg, pos]
            encoded = (cleaned == pos).astype(int)
            return encoded, label_map, target_names
        else:
            # If > 2 classes but binary requested, map non-benign to malicious (1)
            benign_matches = [v for v in distinct if v.lower() in {"benign", "normal", "0", "false"}]
            if not benign_matches:
                raise ValueError(
                    f"Dataset has {len(distinct)} classes and no clear 'benign' class found. "
                    f"Classes: {distinct}. Set multiclass=True or specify binary mapping."
                )
            benign_val = benign_matches[0]
            encoded = (cleaned != benign_val).astype(int)
            label_map = {benign_val: 0, "Attack/Malicious": 1}
            target_names = [benign_val, "Attack/Malicious"]
            return encoded, label_map, target_names
    else:
        # Multi-class target mode
        # Put benign/normal first as class 0 if present
        benign_matches = [v for v in distinct if v.lower() in {"benign", "normal", "0", "false"}]
        ordered_classes = []
        if benign_matches:
            ordered_classes.append(benign_matches[0])
        for c in distinct:
            if c not in ordered_classes:
                ordered_classes.append(c)

        label_map = {cls_name: idx for idx, cls_name in enumerate(ordered_classes)}
        encoded = cleaned.map(label_map).astype(int)
        return encoded, label_map, ordered_classes


def prepare_data(
    frame: pd.DataFrame,
    label_column: str = "label",
    test_size: float = 0.25,
    random_state: int = 42,
    positive_label: str | None = None,
    extra_drop_columns: Iterable[str] = (),
    multiclass: bool = False,
    dedup_policy: DeduplicationPolicy | str = DeduplicationPolicy.REMOVE_EXACT,
    split_strategy: SplitStrategy | str = SplitStrategy.STRATIFIED,
    time_column: str | None = None,
    group_column: str | None = None,
) -> PreparedData:
    """Validate flow data then make a leakage-safe holdout split.

    Args:
        frame: Raw pandas DataFrame.
        label_column: Target column name.
        test_size: Holdout fraction (0 < test_size < 0.5).
        random_state: Random seed for reproducibility.
        positive_label: Exact target value meaning malicious in binary mode.
        extra_drop_columns: Explicit list of column names to drop.
        multiclass: Whether to preserve multi-class attack categories.
        dedup_policy: DeduplicationPolicy ('remove_exact' or 'keep_all').
        split_strategy: Partitioning method ('stratified', 'temporal', 'group').
        time_column: Optional column for temporal split.
        group_column: Optional column for group-aware split.

    Returns:
        PreparedData object containing partitioned feature sets and metadata notes.
    """
    if not 0 < test_size < 0.5:
        raise ValueError("test_size must be greater than 0 and less than 0.5")

    data = frame.copy()
    data.columns = [str(c).strip() for c in data.columns]

    if label_column not in data.columns:
        raise ValueError(f"Label column {label_column!r} is absent. Available columns: {list(data.columns)}")

    # Drop records with missing label
    data = data.dropna(subset=[label_column]).reset_index(drop=True)
    y_encoded, label_map, target_names = _encode_target(
        data[label_column], positive_label=positive_label, multiclass=multiclass
    )
    notes: list[str] = []

    # Detect and drop leakage columns and requested drop columns
    requested = {c.strip() for c in extra_drop_columns}
    automatic = set(detect_target_leakage(list(data.columns), label_column))
    to_drop = (requested | automatic | {label_column}) & set(data.columns)
    
    candidate = data.drop(columns=list(to_drop), errors="ignore")

    # Select numeric features and replace infinite values with NaN
    numeric = candidate.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan)
    ignored = sorted(set(candidate.columns) - set(numeric.columns))

    if ignored:
        notes.append("Ignored non-numeric columns: " + ", ".join(ignored))
    if automatic:
        notes.append("Dropped possible target/leakage columns: " + ", ".join(sorted(automatic)))
    if requested - set(data.columns):
        notes.append("Requested drop columns not found: " + ", ".join(sorted(requested - set(data.columns))))

    if numeric.shape[1] == 0:
        raise ValueError("No numeric feature columns remain. Convert appropriate flow measurements to numbers.")

    # Deduplication policy
    combined = numeric.copy()
    combined["__target__"] = y_encoded.to_numpy()
    before_rows = len(combined)

    policy_str = str(dedup_policy).lower()
    if policy_str == DeduplicationPolicy.REMOVE_EXACT or policy_str == "remove_exact":
        combined = combined.drop_duplicates(subset=list(numeric.columns), keep="first")
        removed = before_rows - len(combined)
        if removed > 0:
            notes.append(f"Removed {removed} exact duplicate feature rows before splitting to prevent cross-split leakage.")
    else:
        notes.append("Kept all duplicate feature rows per explicit deduplication policy.")

    X = combined.drop(columns="__target__")
    y = combined["__target__"].astype(int)

    if y.value_counts().min() < 2:
        raise ValueError("Each class needs at least two rows after validation/deduplication.")

    # Splitting
    temp_df = X.copy()
    temp_df["__target__"] = y
    X_train, X_test, y_train, y_test, split_notes = split_dataset(
        temp_df,
        label_column="__target__",
        strategy=split_strategy,
        test_size=test_size,
        random_state=random_state,
        time_column=time_column,
        group_column=group_column,
    )
    notes.extend(split_notes)

    return PreparedData(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        feature_names=list(X.columns),
        notes=notes,
        label_mapping=label_map,
        target_names=target_names,
        is_multiclass=multiclass or len(target_names) > 2,
    )
