"""Cross-dataset generalization and domain shift research for NetSentry AI.

What it does:
    Aligns semantically equivalent flow features between disparate network benchmark
    datasets (e.g. CIC-IDS2017 and UNSW-NB15), trains an intrusion detector on the
    source domain, and tests generalization on the unseen target domain.

Why it is needed:
    Academic models frequently boast 99%+ accuracy when tested on holdout splits from
    the same capture environment (lab testbeds). However, when deployed to a different
    organization's network or a different dataset, performance degrades dramatically
    due to covariate and concept domain shifts. Cross-dataset testing provides an honest
    measure of real-world generalization.

DCN / ML connection:
    Different capture environments have different background traffic profiles (e.g.,
    enterprise office HTTP vs university research labs), MTU sizes, and packet rates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from ..data.loader import detect_schema_family
from ..data.preprocessor import prepare_data
from ..evaluation.metrics import evaluate_predictions, ModelMetrics
from ..models.factory import build_pipeline


COMMON_NETWORK_FLOW_MAPPING = {
    "CIC-IDS2017": {
        "duration_sec": lambda df: df["Flow Duration"] / 1000.0,
        "fwd_packets": lambda df: df["Total Fwd Packets"],
        "bwd_packets": lambda df: df["Total Backward Packets"],
        "byte_rate": lambda df: df["Flow Bytes/s"],
        "packet_rate": lambda df: df["Flow Packets/s"],
        "avg_packet_size": lambda df: df["Average Packet Size"],
        "label": lambda df: np.where(df["Label"].astype(str).str.upper() == "BENIGN", 0, 1),
    },
    "UNSW-NB15": {
        "duration_sec": lambda df: df["dur"],
        "fwd_packets": lambda df: df["spkts"],
        "bwd_packets": lambda df: df["dpkts"],
        "byte_rate": lambda df: (df["sbytes"] + df["dbytes"]) / df["dur"].replace(0, 0.001),
        "packet_rate": lambda df: df["rate"],
        "avg_packet_size": lambda df: (df["sbytes"] + df["dbytes"]) / (df["spkts"] + df["dpkts"]).replace(0, 1),
        "label": lambda df: np.where(df["attack_cat"].astype(str).str.lower() == "normal", 0, 1),
    },
    "NetSentry-Demo": {
        "duration_sec": lambda df: df["flow_duration_ms"] / 1000.0,
        "fwd_packets": lambda df: df["total_fwd_packets"],
        "bwd_packets": lambda df: df["total_backward_packets"],
        "byte_rate": lambda df: df["flow_bytes_per_second"],
        "packet_rate": lambda df: df["flow_packets_per_second"],
        "avg_packet_size": lambda df: df["average_packet_size"],
        "label": lambda df: np.where(df["label"].astype(str).str.lower() == "benign", 0, 1),
    },
}

SHARED_FEATURES = [
    "duration_sec",
    "fwd_packets",
    "bwd_packets",
    "byte_rate",
    "packet_rate",
    "avg_packet_size",
]


@dataclass
class CrossDatasetResult:
    """Findings and degradation metrics from cross-dataset domain evaluation."""
    source_name: str
    target_name: str
    model_name: str
    shared_features_used: list[str]
    in_domain_metrics: ModelMetrics
    cross_domain_metrics: ModelMetrics
    f1_drop_pct: float
    accuracy_drop_pct: float
    domain_shift_analysis: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_dataset": self.source_name,
            "target_dataset": self.target_name,
            "model_tested": self.model_name,
            "shared_features": self.shared_features_used,
            "in_domain_macro_f1": round(self.in_domain_metrics.f1_macro, 4),
            "cross_domain_macro_f1": round(self.cross_domain_metrics.f1_macro, 4),
            "f1_drop_pct": round(self.f1_drop_pct, 2),
            "in_domain_accuracy": round(self.in_domain_metrics.accuracy, 4),
            "cross_domain_accuracy": round(self.cross_domain_metrics.accuracy, 4),
            "accuracy_drop_pct": round(self.accuracy_drop_pct, 2),
            "domain_shift_analysis": self.domain_shift_analysis,
        }


def extract_shared_features(df: pd.DataFrame, schema_family: str) -> pd.DataFrame:
    """Map raw schema columns to standardized semantic network flow features."""
    if schema_family not in COMMON_NETWORK_FLOW_MAPPING:
        raise ValueError(
            f"Schema '{schema_family}' is not supported for cross-dataset mapping. "
            f"Supported schemas: {list(COMMON_NETWORK_FLOW_MAPPING.keys())}"
        )

    mapping = COMMON_NETWORK_FLOW_MAPPING[schema_family]
    std_df = pd.DataFrame()
    for feat in SHARED_FEATURES:
        std_df[feat] = mapping[feat](df)
    std_df["__target__"] = mapping["label"](df)
    return std_df


def evaluate_cross_dataset(
    source_df: pd.DataFrame,
    target_df: pd.DataFrame,
    source_name: str = "Source",
    target_name: str = "Target",
    model_key: str = "random_forest_500",
    random_state: int = 42,
) -> CrossDatasetResult:
    """Train on source dataset and evaluate generalization on target dataset.

    Args:
        source_df: DataFrame representing the training domain.
        target_df: DataFrame representing the unseen evaluation domain.
        source_name: Identifier for source dataset.
        target_name: Identifier for target dataset.
        model_key: Algorithm to train.
        random_state: Random seed.

    Returns:
        CrossDatasetResult documenting domain shift degradation.
    """
    src_schema = detect_schema_family(list(source_df.columns))
    tgt_schema = detect_schema_family(list(target_df.columns))

    src_std = extract_shared_features(source_df, src_schema)
    tgt_std = extract_shared_features(target_df, tgt_schema)

    # Clean infinite/NaNs
    src_std = src_std.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    tgt_std = tgt_std.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)

    # Prepare source data
    prep_src = prepare_data(
        src_std,
        label_column="__target__",
        test_size=0.25,
        random_state=random_state,
        split_strategy="stratified",
    )

    # Train model on source training partition only
    pipe = build_pipeline(model_key, random_state=random_state, fast_mode=True)
    pipe.fit(prep_src.X_train, prep_src.y_train)

    # In-domain evaluation on untouched source test set
    in_preds = pipe.predict(prep_src.X_test)
    in_proba = pipe.predict_proba(prep_src.X_test) if hasattr(pipe, "predict_proba") else None
    in_metrics = evaluate_predictions(prep_src.y_test, in_preds, y_proba=in_proba)

    # Cross-domain evaluation on target dataset
    tgt_X = tgt_std[SHARED_FEATURES]
    tgt_y = tgt_std["__target__"]
    tgt_preds = pipe.predict(tgt_X)
    tgt_proba = pipe.predict_proba(tgt_X) if hasattr(pipe, "predict_proba") else None
    cross_metrics = evaluate_predictions(tgt_y, tgt_preds, y_proba=tgt_proba)

    # Measure drop
    f1_drop = ((in_metrics.f1_macro - cross_metrics.f1_macro) / max(in_metrics.f1_macro, 1e-4)) * 100.0
    acc_drop = ((in_metrics.accuracy - cross_metrics.accuracy) / max(in_metrics.accuracy, 1e-4)) * 100.0

    analysis = (
        f"Domain Shift Analysis: Training on {source_name} ({src_schema}) yielded an in-domain "
        f"Macro-F1 of {in_metrics.f1_macro:.3f}. When transferred directly to {target_name} ({tgt_schema}), "
        f"Macro-F1 changed by {f1_drop:.1f}% to {cross_metrics.f1_macro:.3f} (Accuracy changed by {acc_drop:.1f}%). "
        f"This performance degradation demonstrates Covariate Shift: the underlying feature distributions "
        f"(packet rates, average sizes, durations) differ between capture environments even for identical attack concepts."
    )

    return CrossDatasetResult(
        source_name=source_name,
        target_name=target_name,
        model_name=model_key,
        shared_features_used=SHARED_FEATURES,
        in_domain_metrics=in_metrics,
        cross_domain_metrics=cross_metrics,
        f1_drop_pct=f1_drop,
        accuracy_drop_pct=acc_drop,
        domain_shift_analysis=analysis,
    )
