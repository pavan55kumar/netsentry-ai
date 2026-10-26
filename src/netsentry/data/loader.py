"""Data loading, schema inspection, and quality assessment for NetSentry AI.

What it does:
    Loads tabular flow datasets (CSV), checks data integrity, detects schema
    families (e.g. CIC-IDS2017, UNSW-NB15), and generates data quality reports.

Why it is needed:
    Network intrusion datasets commonly suffer from corrupted encodings, infinite
    values from zero-duration divisions, missing values, and hidden label leakage.
    Robust validation catches these issues before training begins.

DCN / ML connection:
    Flow exporters calculate rates (bytes/sec, packets/sec) by dividing by duration.
    If duration is 0, float divisions result in +/- Inf values that crash ML estimators.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import numpy as np
import pandas as pd


@dataclass
class DataQualityReport:
    """Detailed summary of dataset health, structure, and schema compliance."""
    total_rows: int
    total_columns: int
    numeric_columns: list[str]
    categorical_columns: list[str]
    missing_counts: dict[str, int]
    infinite_counts: dict[str, int]
    exact_duplicate_rows: int
    label_distribution: dict[str, int] = field(default_factory=dict)
    detected_schema: str = "custom"
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "total_columns": self.total_columns,
            "numeric_columns_count": len(self.numeric_columns),
            "categorical_columns_count": len(self.categorical_columns),
            "missing_total": sum(self.missing_counts.values()),
            "infinite_total": sum(self.infinite_counts.values()),
            "exact_duplicate_rows": self.exact_duplicate_rows,
            "label_distribution": self.label_distribution,
            "detected_schema": self.detected_schema,
            "warnings": self.warnings,
            "recommendations": self.recommendations,
        }


def load_csv(path: str | Path, nrows: int | None = None) -> pd.DataFrame:
    """Load a flow dataset from CSV with robust encoding and whitespace handling.

    Args:
        path: Path to the CSV file.
        nrows: Optional row limit for fast profiling or laptop evaluation.

    Returns:
        Cleaned pandas DataFrame.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"CSV file not found: {file_path}")

    # Flow headers often have leading/trailing spaces (e.g. CIC-IDS2017 " Destination Port")
    try:
        df = pd.read_csv(file_path, nrows=nrows, low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(file_path, nrows=nrows, low_memory=False, encoding="latin1")

    df.columns = [str(c).strip() for c in df.columns]
    return df


def detect_schema_family(columns: list[str]) -> str:
    """Identify if the dataset belongs to a known benchmark schema."""
    cols_lower = {c.lower() for c in columns}
    if ({"flow duration", "total fwd packets"}.issubset(cols_lower) or "flow bytes/s" in cols_lower) and "dur" not in cols_lower:
        return "CIC-IDS2017"
    if {"dur", "spkts"}.issubset(cols_lower) or "attack_cat" in cols_lower:
        return "UNSW-NB15"
    if {"flow_duration_ms", "total_fwd_packets", "flow_bytes_per_second"}.issubset(cols_lower):
        return "NetSentry-Demo"
    return "Custom-Flow"


def validate_schema(df: pd.DataFrame, label_column: str | None = None) -> DataQualityReport:
    """Perform comprehensive data quality inspection and schema audit.

    Args:
        df: Input DataFrame to inspect.
        label_column: Optional target column to inspect for class balance.

    Returns:
        DataQualityReport object.
    """
    total_rows, total_cols = df.shape
    numeric_cols = list(df.select_dtypes(include=[np.number]).columns)
    cat_cols = [c for c in df.columns if c not in numeric_cols]

    missing = {c: int(df[c].isna().sum()) for c in df.columns if df[c].isna().sum() > 0}
    
    # Calculate infinite values in numeric columns
    inf_counts = {}
    for col in numeric_cols:
        count = int(np.isinf(df[col]).sum())
        if count > 0:
            inf_counts[col] = count

    # Exact duplicates across feature columns
    feature_cols = [c for c in df.columns if c != label_column] if label_column else list(df.columns)
    dup_count = int(df.duplicated(subset=feature_cols).sum())

    label_dist = {}
    warnings = []
    recommendations = []

    if label_column:
        if label_column not in df.columns:
            warnings.append(f"Specified label column '{label_column}' was not found in dataset.")
        else:
            val_counts = df[label_column].dropna().value_counts()
            label_dist = {str(k): int(v) for k, v in val_counts.items()}
            if len(val_counts) < 2:
                warnings.append(f"Label column has fewer than 2 classes: {list(val_counts.keys())}")
            elif len(val_counts) == 2:
                ratio = val_counts.iloc[0] / max(val_counts.iloc[1], 1)
                if ratio > 5:
                    recommendations.append(f"Imbalanced binary classes (ratio {ratio:.1f}:1). Use class weighting or PR-AUC.")
            else:
                recommendations.append(f"Multi-class target detected ({len(val_counts)} classes). Use macro-averaged metrics.")

    if inf_counts:
        warnings.append(f"Found infinite values in {len(inf_counts)} numeric columns (caused by zero flow duration).")
        recommendations.append("Imputation will safely replace +/- Inf with NaNs before statistical imputation.")

    if dup_count > 0:
        recommendations.append(f"{dup_count} exact duplicate rows found. Review whether these represent identical repeated probes or redundant records.")

    schema_family = detect_schema_family(list(df.columns))

    return DataQualityReport(
        total_rows=total_rows,
        total_columns=total_cols,
        numeric_columns=numeric_cols,
        categorical_columns=cat_cols,
        missing_counts=missing,
        infinite_counts=inf_counts,
        exact_duplicate_rows=dup_count,
        label_distribution=label_dist,
        detected_schema=schema_family,
        warnings=warnings,
        recommendations=recommendations,
    )
