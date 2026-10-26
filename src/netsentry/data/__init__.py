"""NetSentry AI Data Subsystem."""
from .loader import load_csv, validate_schema, DataQualityReport
from .synthetic import make_demo_dataset, DEMO_FEATURES
from .splitting import split_dataset, SplitStrategy
from .preprocessor import (
    PreparedData,
    prepare_data,
    detect_target_leakage,
    DeduplicationPolicy,
)

__all__ = [
    "load_csv",
    "validate_schema",
    "DataQualityReport",
    "make_demo_dataset",
    "DEMO_FEATURES",
    "split_dataset",
    "SplitStrategy",
    "PreparedData",
    "prepare_data",
    "detect_target_leakage",
    "DeduplicationPolicy",
]
