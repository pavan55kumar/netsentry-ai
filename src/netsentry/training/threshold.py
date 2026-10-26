"""Decision threshold calibration and alert fatigue optimization for NetSentry AI.

What it does:
    Sweeps classification decision thresholds on validation data to identify the
    optimal operational balance between missed attacks (FNR) and false alarms (FPR).

Why it is needed:
    The standard 0.50 threshold assumes equal costs for false alarms and missed attacks.
    In production Security Operations Centers (SOCs), 10,000 daily false alarms overwhelm
    human analysts (alert fatigue), whereas missing a critical ransomware beacon is fatal.
    Threshold optimization on validation data allows operators to enforce strict FPR limits
    (e.g., FPR < 1.0%) or maximize F1 based on risk tolerance.

DCN / ML connection:
    - Low threshold (e.g., 0.20): Maximum security posture. Flags any anomalous flow packet rate.
    - High threshold (e.g., 0.80): Conservative posture. Only alerts on unambiguous attack signatures.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix


@dataclass
class ThresholdOptimizationResult:
    """Summary of threshold sweep performance and recommended operating points."""
    optimal_threshold_f1: float
    best_f1_score: float
    precision_at_optimal: float
    recall_at_optimal: float
    fpr_at_optimal: float
    threshold_curve: list[dict[str, float]] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "optimal_threshold_f1": round(self.optimal_threshold_f1, 3),
            "best_f1_score": round(self.best_f1_score, 4),
            "precision_at_optimal": round(self.precision_at_optimal, 4),
            "recall_at_optimal": round(self.recall_at_optimal, 4),
            "fpr_at_optimal": round(self.fpr_at_optimal, 4),
            "curve_points_count": len(self.threshold_curve),
            "explanation": self.explanation,
        }


def optimize_decision_threshold(
    pipeline: Any,
    X_val: pd.DataFrame | np.ndarray,
    y_val: pd.Series | np.ndarray,
    target_max_fpr: float | None = None,
) -> ThresholdOptimizationResult:
    """Evaluate decision thresholds across validation probabilities.

    Args:
        pipeline: Fitted pipeline with predict_proba support.
        X_val: Validation feature set.
        y_val: Validation ground truth (binary: 0=benign, 1=malicious).
        target_max_fpr: Optional constraint on maximum tolerable false positive rate.

    Returns:
        ThresholdOptimizationResult with curves and optimal threshold recommendation.
    """
    y_true = np.asarray(y_val).astype(int)
    if not hasattr(pipeline, "predict_proba"):
        return ThresholdOptimizationResult(
            optimal_threshold_f1=0.5,
            best_f1_score=0.0,
            precision_at_optimal=0.0,
            recall_at_optimal=0.0,
            fpr_at_optimal=0.0,
            explanation="Model does not support predict_proba; default 0.5 threshold maintained.",
        )

    probs = pipeline.predict_proba(X_val)
    pos_probs = probs[:, 1] if probs.ndim > 1 else probs

    thresholds = np.linspace(0.05, 0.95, 91)
    curve = []

    best_thresh = 0.50
    best_f1 = -1.0
    best_p = 0.0
    best_r = 0.0
    best_fpr = 0.0

    for t in thresholds:
        preds = (pos_probs >= t).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(y_true, preds, average="binary", zero_division=0)
        cm = confusion_matrix(y_true, preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        point = {
            "threshold": round(float(t), 3),
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f1), 4),
            "fpr": round(float(fpr), 4),
        }
        curve.append(point)

        # Selection criteria: maximize F1, subject to target_max_fpr if specified
        if target_max_fpr is not None:
            if fpr <= target_max_fpr and f1 > best_f1:
                best_f1 = float(f1)
                best_thresh = float(t)
                best_p = float(p)
                best_r = float(r)
                best_fpr = float(fpr)
        else:
            if f1 > best_f1:
                best_f1 = float(f1)
                best_thresh = float(t)
                best_p = float(p)
                best_r = float(r)
                best_fpr = float(fpr)

    explanation = (
        f"Calibrated optimal decision threshold is {best_thresh:.2f}. "
        f"At this operating point, Macro-F1 reaches {best_f1:.3f} with "
        f"{best_p * 100:.1f}% precision, {best_r * 100:.1f}% recall, and "
        f"{best_fpr * 100:.2f}% false alarm rate (FPR)."
    )

    return ThresholdOptimizationResult(
        optimal_threshold_f1=best_thresh,
        best_f1_score=best_f1,
        precision_at_optimal=best_p,
        recall_at_optimal=best_r,
        fpr_at_optimal=best_fpr,
        threshold_curve=curve,
        explanation=explanation,
    )
