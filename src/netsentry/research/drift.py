"""Model drift simulation and covariate shift analysis for NetSentry AI.

What it does:
    Simulates controlled statistical distribution shifts (covariate shift) across
    network traffic features over time, and measures the resulting performance
    degradation on trained intrusion models.

Why it is needed:
    Real-world networks are never static. As organizations upgrade internet bandwidth,
    adopt new enterprise software, or change video streaming protocols, normal flow
    rates and packet sizes drift over months. Models trained on historical data begin
    generating false alarms or missing altered attacks. Measuring drift resilience
    informs retraining schedules.

DCN / ML connection:
    Simulates volumetric rate amplification (bandwidth upgrades), protocol flag
    mutations, and flow duration shifts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from ..evaluation.metrics import evaluate_predictions


@dataclass
class DriftSimulationResult:
    """Findings from systematic traffic drift evaluation."""
    drift_type: str
    intensities: list[float]  # e.g. [0.0, 0.25, 0.50, 1.0, 2.0]
    macro_f1_scores: list[float]
    accuracies: list[float]
    false_positive_rates: list[float]
    baseline_f1: float
    final_f1: float
    degradation_pct: float
    analysis: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "drift_type": self.drift_type,
            "intensities": self.intensities,
            "macro_f1_scores": [round(s, 4) for s in self.macro_f1_scores],
            "accuracies": [round(a, 4) for a in self.accuracies],
            "false_positive_rates": [round(f, 4) for f in self.false_positive_rates],
            "baseline_f1": round(self.baseline_f1, 4),
            "final_f1": round(self.final_f1, 4),
            "degradation_pct": round(self.degradation_pct, 2),
            "analysis": self.analysis,
        }


def simulate_model_drift(
    pipeline: Pipeline,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    drift_type: str = "volumetric_spike",
    intensities: list[float] | None = None,
    random_state: int = 42,
) -> DriftSimulationResult:
    """Simulate covariate drift on test traffic and evaluate model resilience.

    Args:
        pipeline: Fitted scikit-learn Pipeline.
        X_test: Holdout test features.
        y_test: Holdout test labels.
        drift_type: 'volumetric_spike' (byte/packet rate drift), 'flag_shift', or 'noise_corruption'.
        intensities: Multipliers of shift magnitude (e.g. 0.0 to 2.0).
        random_state: Seed for reproducibility.

    Returns:
        DriftSimulationResult object.
    """
    np.random.seed(random_state)
    if intensities is None:
        intensities = [0.0, 0.25, 0.50, 1.0, 1.5, 2.0]

    f1_list = []
    acc_list = []
    fpr_list = []

    rate_cols = [c for c in X_test.columns if any(k in c.lower() for k in ["rate", "byte", "packet", "speed"])]
    flag_cols = [c for c in X_test.columns if any(k in c.lower() for k in ["flag", "syn", "rst", "ack"])]

    for alpha in intensities:
        drifted_X = X_test.copy()
        if alpha > 0.0:
            if drift_type == "volumetric_spike":
                # Scale traffic rates upward with added variance (e.g. bandwidth upgrade)
                for col in rate_cols:
                    multiplier = 1.0 + (alpha * np.random.uniform(0.8, 1.5, size=len(drifted_X)))
                    drifted_X[col] = drifted_X[col] * multiplier

            elif drift_type == "flag_shift":
                # Perturb flag counts
                for col in flag_cols:
                    noise = np.random.poisson(lam=alpha, size=len(drifted_X))
                    drifted_X[col] = drifted_X[col] + noise

            else:  # noise_corruption
                # Gaussian jitter on all features
                for col in drifted_X.select_dtypes(include=[np.number]).columns:
                    std_val = float(drifted_X[col].std()) if float(drifted_X[col].std()) > 0 else 1.0
                    jitter = np.random.normal(0, std_val * 0.2 * alpha, size=len(drifted_X))
                    drifted_X[col] = np.maximum(drifted_X[col] + jitter, 0.0)

        preds = pipeline.predict(drifted_X)
        metrics = evaluate_predictions(y_test, preds)
        f1_list.append(metrics.f1_macro)
        acc_list.append(metrics.accuracy)
        fpr_list.append(metrics.false_positive_rate)

    base_f1 = f1_list[0]
    final_f1 = f1_list[-1]
    deg_pct = ((base_f1 - final_f1) / max(base_f1, 1e-4)) * 100.0

    analysis = (
        f"Simulated {drift_type.replace('_', ' ').title()}: As drift intensity progressed from 0% to "
        f"{intensities[-1] * 100:.0f}%, Macro-F1 degraded by {deg_pct:.1f}% (from {base_f1:.3f} down to {final_f1:.3f}). "
        f"False Positive Rate rose to {fpr_list[-1] * 100:.1f}%. "
        f"This confirms that the model's decision boundaries are sensitive to background traffic shifts, "
        f"mandating automated drift monitoring and scheduled retrain cycles."
    )

    return DriftSimulationResult(
        drift_type=drift_type,
        intensities=intensities,
        macro_f1_scores=f1_list,
        accuracies=acc_list,
        false_positive_rates=fpr_list,
        baseline_f1=base_f1,
        final_f1=final_f1,
        degradation_pct=deg_pct,
        analysis=analysis,
    )
