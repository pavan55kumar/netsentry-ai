"""Scientific evaluation metrics and benchmark calculation for NetSentry AI.

What it does:
    Computes rigorous performance metrics across binary and multi-class intrusion models:
    - Balanced metrics: Macro-F1, Weighted-F1, Precision-Recall AUC, ROC-AUC.
    - Security-critical metrics: False Positive Rate (FPR), False Negative Rate (FNR).
    - Per-class breakdowns for granular threat identification.
    - Operational engineering metrics: Training time, inference latency (ms/flow), model memory size.

Why it is needed:
    In network intrusion detection, datasets are overwhelmingly benign (often 95-99% normal).
    A naive model that predicts "benign" on every packet achieves 99% accuracy while letting
    100% of attacks penetrate the network. High FPR causes security analyst alert fatigue,
    causing real attacks to be ignored. High FNR allows stealthy compromise.

DCN / ML connection:
    In high-speed edge firewalls processing millions of flows/sec, inference latency must
    be under milliseconds to prevent packet queue drops and buffer overflows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import io
import time
from typing import Any
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    auc,
    confusion_matrix,
    precision_recall_curve,
    precision_recall_fscore_support,
    roc_auc_score,
)


@dataclass
class ModelMetrics:
    """Comprehensive performance assessment across statistical and operational metrics."""
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    f1_weighted: float
    false_positive_rate: float
    false_negative_rate: float
    confusion_matrix: list[list[int]]
    per_class: dict[str, dict[str, float]] = field(default_factory=dict)
    roc_auc: float | None = None
    pr_auc: float | None = None
    training_duration_sec: float = 0.0
    inference_latency_ms: float = 0.0
    model_size_kb: float = 0.0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_positives: int = 0
    precision_malicious: float = 0.0
    recall_malicious: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "accuracy": round(self.accuracy, 4),
            "precision_macro": round(self.precision_macro, 4),
            "recall_macro": round(self.recall_macro, 4),
            "macro_f1": round(self.f1_macro, 4),
            "weighted_f1": round(self.f1_weighted, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "roc_auc": round(self.roc_auc, 4) if self.roc_auc is not None else None,
            "pr_auc": round(self.pr_auc, 4) if self.pr_auc is not None else None,
            "training_duration_sec": round(self.training_duration_sec, 3),
            "inference_latency_ms": round(self.inference_latency_ms, 4),
            "model_size_kb": round(self.model_size_kb, 2),
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_positives": self.true_positives,
            "precision_malicious": round(self.precision_malicious, 4),
            "recall_malicious": round(self.recall_malicious, 4),
            "per_class": self.per_class,
            "confusion_matrix": self.confusion_matrix,
        }


def evaluate_predictions(
    y_true: np.ndarray | pd.Series,
    y_pred: np.ndarray | pd.Series,
    y_proba: np.ndarray | None = None,
    target_names: list[str] | None = None,
    training_duration_sec: float = 0.0,
    inference_latency_ms: float = 0.0,
    model_size_kb: float = 0.0,
) -> ModelMetrics:
    """Compute comprehensive statistical metrics for intrusion detection predictions.

    Args:
        y_true: Ground truth labels (integer encoded).
        y_pred: Predicted class labels.
        y_proba: Predicted class probabilities (optional).
        target_names: Optional human-readable class names.
        training_duration_sec: Measured training duration.
        inference_latency_ms: Measured latency per sample in milliseconds.
        model_size_kb: In-memory/disk serialized model footprint.

    Returns:
        Populated ModelMetrics object.
    """
    y_t = np.asarray(y_true).astype(int)
    y_p = np.asarray(y_pred).astype(int)
    unique_labels = sorted(np.unique(np.concatenate([y_t, y_p])))
    num_classes = len(unique_labels)

    acc = float(accuracy_score(y_t, y_p))

    # Macro & weighted averages
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
        y_t, y_p, average="macro", zero_division=0
    )
    _, _, f1_weighted, _ = precision_recall_fscore_support(
        y_t, y_p, average="weighted", zero_division=0
    )

    # Per-class metrics
    p_per, r_per, f1_per, sup_per = precision_recall_fscore_support(
        y_t, y_p, labels=unique_labels, zero_division=0
    )

    names = target_names if target_names and len(target_names) == num_classes else [f"Class {i}" for i in unique_labels]
    per_class_dict = {}
    for i, lbl in enumerate(unique_labels):
        c_name = names[i] if i < len(names) else f"Class {lbl}"
        per_class_dict[c_name] = {
            "precision": float(p_per[i]),
            "recall": float(r_per[i]),
            "f1": float(f1_per[i]),
            "support": int(sup_per[i]),
        }

    # Confusion matrix
    cm = confusion_matrix(y_t, y_p, labels=unique_labels)

    # Binary vs Multi-class specific calculations
    tn = fp = fn = tp = 0
    fpr = fnr = 0.0
    p_mal = r_mal = 0.0

    if num_classes <= 2:
        if cm.shape == (2, 2):
            tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        p_mal = float(per_class_dict.get(names[-1], {}).get("precision", 0.0))
        r_mal = float(per_class_dict.get(names[-1], {}).get("recall", 0.0))
    else:
        # Multi-class: Macro-average FPR across classes
        # For each class i: FP is sum of column i minus CM[i,i]; TN is all other entries
        fpr_list = []
        for i in range(num_classes):
            c_tp = cm[i, i]
            c_fp = cm[:, i].sum() - c_tp
            c_fn = cm[i, :].sum() - c_tp
            c_tn = cm.sum() - (c_tp + c_fp + c_fn)
            fpr_list.append(float(c_fp / (c_fp + c_tn)) if (c_fp + c_tn) > 0 else 0.0)
        fpr = float(np.mean(fpr_list))
        fnr = float(1.0 - r_macro)

    # ROC-AUC & PR-AUC calculation
    roc_auc_val: float | None = None
    pr_auc_val: float | None = None

    if y_proba is not None:
        try:
            if num_classes == 2:
                # Binary probabilities: column 1
                pos_proba = y_proba[:, 1] if y_proba.ndim > 1 else y_proba
                roc_auc_val = float(roc_auc_score(y_t, pos_proba))
                prec_curve, rec_curve, _ = precision_recall_curve(y_t, pos_proba)
                pr_auc_val = float(auc(rec_curve, prec_curve))
            elif num_classes > 2 and y_proba.ndim > 1:
                # Multi-class OvR ROC-AUC
                roc_auc_val = float(roc_auc_score(y_t, y_proba, multi_class="ovr", average="macro"))
        except Exception:
            roc_auc_val = None
            pr_auc_val = None

    return ModelMetrics(
        accuracy=float(acc),
        precision_macro=float(p_macro),
        recall_macro=float(r_macro),
        f1_macro=float(f1_macro),
        f1_weighted=float(f1_weighted),
        false_positive_rate=float(fpr),
        false_negative_rate=float(fnr),
        confusion_matrix=cm.tolist(),
        per_class=per_class_dict,
        roc_auc=roc_auc_val,
        pr_auc=pr_auc_val,
        training_duration_sec=training_duration_sec,
        inference_latency_ms=inference_latency_ms,
        model_size_kb=model_size_kb,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        true_positives=tp,
        precision_malicious=p_mal,
        recall_malicious=r_mal,
    )


def calculate_inference_latency(pipeline: Any, X: pd.DataFrame | np.ndarray, repetitions: int = 3) -> float:
    """Measure inference latency per sample in milliseconds."""
    sample = X.iloc[:min(len(X), 500)] if isinstance(X, pd.DataFrame) else X[:min(len(X), 500)]
    # Warmup
    _ = pipeline.predict(sample)

    start = time.perf_counter()
    for _ in range(repetitions):
        _ = pipeline.predict(sample)
    total_time = time.perf_counter() - start

    total_samples = len(sample) * repetitions
    latency_ms = (total_time / total_samples) * 1000.0
    return float(latency_ms)


def measure_model_size_kb(pipeline: Any) -> float:
    """Measure serialized disk footprint of fitted pipeline in kilobytes."""
    buf = io.BytesIO()
    joblib.dump(pipeline, buf)
    size_bytes = buf.tell()
    return float(size_bytes / 1024.0)


def metrics_for_backward_compat(y_true, y_pred) -> tuple[dict[str, float], list[list[int]]]:
    """Backward-compatible metrics calculator matching legacy NetSentry return signature."""
    metrics = evaluate_predictions(y_true, y_pred)
    legacy_dict = {
        "accuracy": metrics.accuracy,
        "precision_malicious": metrics.precision_malicious,
        "recall_malicious": metrics.recall_malicious,
        "macro_f1": metrics.f1_macro,
        "false_positive_rate": metrics.false_positive_rate,
        "true_negatives": metrics.true_negatives,
        "false_positives": metrics.false_positives,
        "false_negatives": metrics.false_negatives,
        "true_positives": metrics.true_positives,
    }
    return legacy_dict, metrics.confusion_matrix

