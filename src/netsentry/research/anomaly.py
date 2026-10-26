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


@dataclass
class UnseenAttackResult:
    """Findings from holding out an entire attack category from training."""
    held_out_attack: str
    total_unseen_samples: int
    supervised_recall_on_unseen: float
    unsupervised_recall_on_unseen: float
    supervised_benign_fpr: float
    unsupervised_benign_fpr: float
    findings: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "held_out_attack": self.held_out_attack,
            "total_unseen_samples": self.total_unseen_samples,
            "supervised_recall_on_unseen": round(self.supervised_recall_on_unseen, 4),
            "unsupervised_recall_on_unseen": round(self.unsupervised_recall_on_unseen, 4),
            "supervised_benign_fpr": round(self.supervised_benign_fpr, 4),
            "unsupervised_benign_fpr": round(self.unsupervised_benign_fpr, 4),
            "findings": self.findings,
        }


def evaluate_unseen_attack_detection(
    df: pd.DataFrame,
    label_column: str,
    held_out_attack: str,
    benign_label: str = "BENIGN",
    random_state: int = 42,
) -> UnseenAttackResult:
    """Hold out an attack category during supervised training and test zero-day detection.

    Args:
        df: Input DataFrame with flow features and labels.
        label_column: Target label column name.
        held_out_attack: Attack category to hide from training set.
        benign_label: Label name designating normal benign traffic.
        random_state: Seed for reproducibility.

    Returns:
        UnseenAttackResult comparing supervised vs unsupervised detection on novel attacks.
    """
    clean_df = df.copy()
    clean_df.columns = [str(c).strip() for c in clean_df.columns]
    
    # Identify non-numeric columns to drop (except label)
    feat_cols = [c for c in clean_df.select_dtypes(include=[np.number]).columns if c != label_column]
    clean_df[feat_cols] = clean_df[feat_cols].replace([np.inf, -np.inf], np.nan)
    
    # Split into train pool (excluding held_out_attack) and test pool
    unseen_df = clean_df[clean_df[label_column].astype(str).str.lower() == held_out_attack.lower()].copy()
    known_df = clean_df[clean_df[label_column].astype(str).str.lower() != held_out_attack.lower()].copy()
    
    if len(unseen_df) == 0:
        raise ValueError(f"Held-out attack '{held_out_attack}' not found in dataset. Available: {list(clean_df[label_column].unique())}")

    # Partition known data: 75% train, 25% test
    from sklearn.model_selection import train_test_split
    known_train, known_test = train_test_split(known_df, test_size=0.25, random_state=random_state)
    
    # Construct test evaluation set: known_test + unseen_df
    eval_df = pd.concat([known_test, unseen_df], ignore_index=True)
    
    # Binary ground truth for evaluation: 0 = Benign, 1 = Any Attack (including unseen!)
    y_eval = np.where(eval_df[label_column].astype(str).str.lower() == benign_label.lower(), 0, 1)
    is_unseen_mask = (eval_df[label_column].astype(str).str.lower() == held_out_attack.lower()).to_numpy()
    is_benign_mask = (eval_df[label_column].astype(str).str.lower() == benign_label.lower()).to_numpy()

    # Supervised training data: label 0 = Benign, 1 = Known Attack
    y_known_train = np.where(known_train[label_column].astype(str).str.lower() == benign_label.lower(), 0, 1)

    # 1. Supervised Model (Trained without ever seeing held_out_attack!)
    sup_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", RandomForestClassifier(n_estimators=100, random_state=random_state, n_jobs=-1)),
    ])
    sup_pipe.fit(known_train[feat_cols], y_known_train)
    sup_preds = sup_pipe.predict(eval_df[feat_cols])

    # 2. Unsupervised Isolation Forest (Fitted on Benign training traffic only)
    benign_train = known_train[known_train[label_column].astype(str).str.lower() == benign_label.lower()]
    unsup_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", RobustScaler()),
        ("model", IsolationForest(n_estimators=150, contamination=0.10, random_state=random_state, n_jobs=-1)),
    ])
    unsup_pipe.fit(benign_train[feat_cols])
    raw_unsup_preds = unsup_pipe.predict(eval_df[feat_cols])
    unsup_preds = np.where(raw_unsup_preds == -1, 1, 0)

    # Calculate metrics on the unseen attack subset specifically!
    sup_unseen_recall = float((sup_preds[is_unseen_mask] == 1).mean()) if is_unseen_mask.sum() > 0 else 0.0
    unsup_unseen_recall = float((unsup_preds[is_unseen_mask] == 1).mean()) if is_unseen_mask.sum() > 0 else 0.0
    
    sup_benign_fpr = float((sup_preds[is_benign_mask] == 1).mean()) if is_benign_mask.sum() > 0 else 0.0
    unsup_benign_fpr = float((unsup_preds[is_benign_mask] == 1).mean()) if is_benign_mask.sum() > 0 else 0.0

    findings = (
        f"Zero-Day Simulation for '{held_out_attack}' ({len(unseen_df)} flows): "
        f"The supervised model achieved {sup_unseen_recall * 100:.1f}% recall on the novel attack, "
        f"whereas the unsupervised Isolation Forest achieved {unsup_unseen_recall * 100:.1f}% recall. "
        f"However, the unsupervised detector incurred a {unsup_benign_fpr * 100:.1f}% false alarm rate on benign traffic "
        f"compared to {sup_benign_fpr * 100:.1f}% for the supervised baseline. "
        f"CRITICAL RESEARCH DISTINCTION: An anomaly flag indicates statistical distance from baseline traffic, "
        f"NOT confirmed proof of maliciousness."
    )

    return UnseenAttackResult(
        held_out_attack=held_out_attack,
        total_unseen_samples=len(unseen_df),
        supervised_recall_on_unseen=sup_unseen_recall,
        unsupervised_recall_on_unseen=unsup_unseen_recall,
        supervised_benign_fpr=sup_benign_fpr,
        unsupervised_benign_fpr=unsup_benign_fpr,
        findings=findings,
    )

