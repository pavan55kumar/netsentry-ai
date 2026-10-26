"""Synthetic network flow generation for NetSentry AI educational demos.

What it does:
    Generates synthetic tabular flow records with realistic numeric ranges
    for rapid, zero-download experimentation.

Why it is needed:
    Enables students to test complete ML training and inference pipelines
    locally without downloading multi-gigabyte PCAP files or public datasets.

DCN / ML connection:
    Simulates flow-level metrics (packet counts, byte rates, TCP flags)
    and class imbalance commonly seen in network intrusion scenarios.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.datasets import make_classification

DEMO_FEATURES = [
    "flow_duration_ms",
    "total_fwd_packets",
    "total_backward_packets",
    "flow_bytes_per_second",
    "flow_packets_per_second",
    "syn_flag_count",
    "rst_flag_count",
    "average_packet_size",
]


def make_demo_dataset(rows: int = 1200, random_state: int = 42) -> pd.DataFrame:
    """Create synthetic flows only for a runnable demo, never for real-world claims.

    Args:
        rows: Number of flow records to generate.
        random_state: Seed for reproducibility.

    Returns:
        DataFrame containing numeric flow features and binary string labels.
    """
    X, y = make_classification(
        n_samples=rows,
        n_features=len(DEMO_FEATURES),
        n_informative=6,
        n_redundant=1,
        weights=[0.72, 0.28],
        class_sep=1.0,
        flip_y=0.04,
        random_state=random_state,
    )
    frame = pd.DataFrame(X, columns=DEMO_FEATURES)
    for column in [
        "flow_duration_ms",
        "total_fwd_packets",
        "total_backward_packets",
        "flow_bytes_per_second",
        "flow_packets_per_second",
        "average_packet_size",
    ]:
        frame[column] = np.abs(frame[column] * 100).round(3)
    frame["syn_flag_count"] = np.clip(np.rint(frame["syn_flag_count"] + 2), 0, None)
    frame["rst_flag_count"] = np.clip(np.rint(frame["rst_flag_count"] + 1), 0, None)
    frame["label"] = np.where(y == 1, "malicious", "benign")
    return frame
