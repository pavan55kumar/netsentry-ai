"""Data generation, validation, and leakage-aware preparation for NetSentry AI.

This module provides backward-compatible access to the netsentry.data subsystem.
"""
from __future__ import annotations

from .data.synthetic import DEMO_FEATURES, make_demo_dataset
from .data.loader import load_csv, validate_schema, DataQualityReport
from .data.splitting import split_dataset, SplitStrategy
from .data.preprocessor import (
    PreparedData,
    prepare_data,
    detect_target_leakage,
    DeduplicationPolicy,
    _encode_target,
)


def _binary_target(series, positive_label: str | None = None):
    """Backward-compatible wrapper for binary target encoding."""
    encoded, _, _ = _encode_target(series, positive_label=positive_label, multiclass=False)
    return encoded


__all__ = [
    "DEMO_FEATURES",
    "make_demo_dataset",
    "load_csv",
    "validate_schema",
    "DataQualityReport",
    "split_dataset",
    "SplitStrategy",
    "PreparedData",
    "prepare_data",
    "detect_target_leakage",
    "DeduplicationPolicy",
    "_binary_target",
]
