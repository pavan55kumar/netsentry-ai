"""Scientific dataset partitioning strategies for NetSentry AI.

What it does:
    Provides three scientifically rigorous splitting mechanisms:
    1. Stratified random splitting (preserves class distributions).
    2. Temporal chronological splitting (evaluates generalization to future traffic).
    3. Group-aware splitting (prevents session or host leakage across splits).

Why it is needed:
    In network security ML, naive random splitting frequently leaks information
    because packets or flows from the same attacker/session appear in both train
    and test sets. A temporal or group split provides an honest measure of real-world
    threat detection generalization.

DCN / ML connection:
    Attackers execute multi-stage campaigns across minutes or hours. Evaluating
    on later time slices tests whether a model detects evolving campaigns without
    memorizing identical attack session timestamps.
"""
from __future__ import annotations

from enum import Enum
from typing import Tuple
import pandas as pd
from sklearn.model_selection import train_test_split, GroupShuffleSplit


class SplitStrategy(str, Enum):
    STRATIFIED = "stratified"
    TEMPORAL = "temporal"
    GROUP = "group"


def split_dataset(
    df: pd.DataFrame,
    label_column: str,
    strategy: SplitStrategy | str = SplitStrategy.STRATIFIED,
    test_size: float = 0.25,
    random_state: int = 42,
    time_column: str | None = None,
    group_column: str | None = None,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, list[str]]:
    """Partition dataset into train and test sets according to chosen scientific methodology.

    Args:
        df: Input DataFrame.
        label_column: Name of the target column.
        strategy: 'stratified', 'temporal', or 'group'.
        test_size: Fraction of data reserved for holdout evaluation (0.1 to 0.4).
        random_state: Seed for reproducible random splitting.
        time_column: Required if strategy is 'temporal'.
        group_column: Required if strategy is 'group'.

    Returns:
        (X_train, X_test, y_train, y_test, split_notes)
    """
    notes: list[str] = []
    strategy_str = str(strategy).lower()

    if label_column not in df.columns:
        raise ValueError(f"Label column '{label_column}' not found.")

    y = df[label_column]
    X = df.drop(columns=[label_column])

    if strategy_str == SplitStrategy.TEMPORAL or strategy_str == "temporal":
        if not time_column or time_column not in df.columns:
            # Fallback to index order if chronological
            notes.append("Temporal split performed based on sequential row index order (chronological arrival).")
            split_idx = int(len(df) * (1.0 - test_size))
            X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
            y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]
        else:
            notes.append(f"Temporal split performed based on ordered timestamps in '{time_column}'.")
            sorted_df = df.sort_values(by=time_column).reset_index(drop=True)
            y_sorted = sorted_df[label_column]
            X_sorted = sorted_df.drop(columns=[label_column, time_column], errors="ignore")
            split_idx = int(len(sorted_df) * (1.0 - test_size))
            X_train, X_test = X_sorted.iloc[:split_idx], X_sorted.iloc[split_idx:]
            y_train, y_test = y_sorted.iloc[:split_idx], y_sorted.iloc[split_idx:]

    elif strategy_str == SplitStrategy.GROUP or strategy_str == "group":
        if not group_column or group_column not in df.columns:
            raise ValueError(f"Group split requested but valid group_column not provided. Found columns: {list(df.columns)}")
        notes.append(f"Group-aware split performed grouping on '{group_column}' to prevent session leakage.")
        groups = df[group_column]
        X_clean = X.drop(columns=[group_column], errors="ignore")
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        train_idx, test_idx = next(gss.split(X_clean, y, groups=groups))
        X_train, X_test = X_clean.iloc[train_idx], X_clean.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    else:
        # Default stratified random holdout
        counts = y.value_counts()
        n_test = int(len(df) * test_size)
        if (counts < 2).any() or n_test < len(counts):
            notes.append("Notice: Test set size smaller than class count; falling back to random holdout split.")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state
            )
        else:
            notes.append(f"Stratified holdout split (test_size={test_size}, random_state={random_state}).")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )

    return X_train, X_test, y_train, y_test, notes
