"""Baseline comparative evaluation and the Accuracy Trap in NetSentry AI.

What it does:
    Computes performance of a naive Zero-R (majority class) dummy classifier on
    the exact same holdout set as research models.

Why it is needed:
    Network security datasets are inherently imbalanced (e.g., 90% benign, 10% attack).
    A naive firewall rule that always declares "benign" automatically achieves 90% accuracy!
    Evaluating against a majority baseline demonstrates why accuracy alone is a deceptive,
    dangerous metric in cybersecurity research, and highlights why Macro-F1 and PR-AUC
    are necessary to evaluate true intrusion detection efficacy.

DCN / ML connection:
    Illustrates the concept of the 'Base Rate Fallacy' in network anomaly detection:
    when attacks are rare, high accuracy hides total blindness to actual intrusions.
"""
from __future__ import annotations

from typing import Any
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from .metrics import evaluate_predictions, ModelMetrics


def evaluate_majority_baseline(
    y_train: pd.Series | np.ndarray,
    y_test: pd.Series | np.ndarray,
    target_names: list[str] | None = None,
) -> dict[str, Any]:
    """Train a naive majority-class dummy classifier and evaluate on the holdout test set.

    Args:
        y_train: Training ground-truth labels.
        y_test: Holdout test ground-truth labels.
        target_names: Optional human-readable class names.

    Returns:
        Dictionary containing baseline metrics and educational commentary.
    """
    dummy = DummyClassifier(strategy="most_frequent")
    # Dummy requires X of same length
    X_dummy = np.zeros((len(y_train), 1))
    dummy.fit(X_dummy, y_train)

    X_test_dummy = np.zeros((len(y_test), 1))
    preds = dummy.predict(X_test_dummy)
    probs = dummy.predict_proba(X_test_dummy)

    metrics = evaluate_predictions(y_test, preds, y_proba=probs, target_names=target_names)

    # Class balance commentary
    unique, counts = np.unique(y_test, return_counts=True)
    dist = {int(k): int(v) for k, v in zip(unique, counts)}
    majority_class_pct = (max(counts) / len(y_test)) * 100.0

    explanation = (
        f"A trivial model predicting the majority class exclusively achieves "
        f"{metrics.accuracy * 100.0:.1f}% accuracy on this test set, but has a "
        f"Macro-F1 of {metrics.f1_macro:.3f} and attack recall of {metrics.recall_malicious:.1f}. "
        f"This demonstrates why accuracy alone is deceptive in network intrusion detection."
    )

    return {
        "baseline_metrics": metrics.to_dict(),
        "majority_class_share_pct": round(majority_class_pct, 2),
        "test_distribution": dist,
        "accuracy_trap_explanation": explanation,
    }
