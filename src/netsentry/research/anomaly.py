"""Unsupervised anomaly detection benchmark vs supervised classification for NetSentry AI.

What it does:
    Trains an Isolation Forest strictly without labels, benchmarks its zero-day
    anomaly detection capabilities against a supervised classifier, and analyzes
    the critical distinction between statistical anomalies and malicious attacks.

Why it is needed:
    Supervised intrusion detection models cannot recognize previously unseen (zero-day)
    attacks whose signatures do not exist in training data. Unsupervised anomaly detection
    flags novel outliers. However, an anomaly is NOT necessarily an attack (e.g. video
    conferences or bulk server backups create statistical anomalies that are completely benign).

DCN / ML connection:
    Connects unsupervised partition depth in feature space to unusual network packet bursts,
    rare port combinations, and irregular inter-arrival times.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler
from sklearn.impute import SimpleImputer

from ..evaluation.metrics import evaluate_predictions, ModelMetrics


@dataclass
class AnomalyBenchmarkResult:
    """Comparative evaluation between unsupervised and supervised detection."""
    supervised_metrics: ModelMetrics
    unsupervised_metrics: ModelMetrics
    zero_day_detection_rate: float  # Recall of attacks without training labels
    benign_false_alarm_rate: float
    educational_insights: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "supervised_macro_f1": round(self.supervised_metrics.f1_macro, 4),
            "unsupervised_macro_f1": round(self.unsupervised_metrics.f1_macro, 4),
            "unsupervised_recall_attacks": round(self.unsupervised_metrics.recall_malicious, 4),
            "unsupervised_fpr_benign": round(self.unsupervised_metrics.false_positive_rate, 4),
            "supervised_accuracy": round(self.supervised_metrics.accuracy, 4),
            "unsupervised_accuracy": round(self.unsupervised_metrics.accuracy, 4),
            "educational_insights": self.educational_insights,
        }


def benchmark_unsupervised_anomaly(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series,
    target_names: list[str] | None = None,
    contamination: float = 0.15,
    random_state: int = 42,
) -> AnomalyBenchmarkResult:
    """Benchmark unsupervised Isolation Forest against supervised Random Forest.

    Args:
        X_train: Training features.
        X_test: Holdout test features.
        y_train: Training labels (used ONLY by supervised model).
        y_test: Holdout test labels (used strictly for evaluation scoring).
        target_names: Class labels.
        contamination: Estimated prior anomaly proportion in traffic.
        random_state: Seed for reproducibility.

    Returns:
        AnomalyBenchmarkResult object.
    """
    # 1. Supervised baseline (Random Forest)
    sup_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", RandomForestClassifier(n_estimators=100, random_state=random_state, n_jobs=-1)),
    ])
    sup_pipe.fit(X_train, y_train)
    sup_preds = sup_pipe.predict(X_test)
    sup_proba = sup_pipe.predict_proba(X_test) if hasattr(sup_pipe, "predict_proba") else None
    sup_metrics = evaluate_predictions(y_test, sup_preds, y_proba=sup_proba, target_names=target_names)

    # 2. Unsupervised Isolation Forest (Fitted WITHOUT y_train!)
    unsup_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", RobustScaler()),
        ("model", IsolationForest(n_estimators=150, contamination=contamination, random_state=random_state, n_jobs=-1)),
    ])
    unsup_pipe.fit(X_train)  # Unsupervised!

    # Score: -1 is anomaly (attack), 1 is normal (benign)
    raw_preds = unsup_pipe.predict(X_test)
    unsup_preds = np.where(raw_preds == -1, 1, 0)

    # Convert decision function to probability-like proxy score
    raw_scores = unsup_pipe.named_steps["model"].decision_function(
        unsup_pipe.named_steps["scaler"].transform(
            unsup_pipe.named_steps["imputer"].transform(X_test)
        )
    )
    min_s, max_s = raw_scores.min(), raw_scores.max()
    norm_scores = 1.0 - ((raw_scores - min_s) / max(max_s - min_s, 1e-6))
    unsup_proba = np.column_stack([1.0 - norm_scores, norm_scores])

    unsup_metrics = evaluate_predictions(y_test, unsup_preds, y_proba=unsup_proba, target_names=target_names)

    insights = [
        f"Zero-Day Discovery: The unsupervised Isolation Forest detected {unsup_metrics.recall_malicious * 100:.1f}% "
        f"of malicious flows WITHOUT ever seeing an attack label during training.",
        f"The False Alarm Penalty: Because it assumes any outlier is an attack, its False Positive Rate (FPR) is "
        f"{unsup_metrics.false_positive_rate * 100:.1f}%, compared to {sup_metrics.false_positive_rate * 100:.1f}% for the supervised model.",
        "Anomaly != Attack Principle: In operational networks, a large scheduled server backup or high-resolution video stream "
        "is statistically anomalous but completely benign. Supervised models learn specific malicious patterns, "
        "whereas unsupervised detectors flag deviations from normality regardless of intent.",
    ]

    return AnomalyBenchmarkResult(
        supervised_metrics=sup_metrics,
        unsupervised_metrics=unsup_metrics,
        zero_day_detection_rate=unsup_metrics.recall_malicious,
        benign_false_alarm_rate=unsup_metrics.false_positive_rate,
        educational_insights=insights,
    )
