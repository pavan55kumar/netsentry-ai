"""Global feature importance and attribution analysis for NetSentry AI.

What it does:
    Computes global feature rankings using Tree Mean Decrease in Impurity (MDI),
    Permutation Importance (model-agnostic), and Linear Model Coefficients.

Why it is needed:
    Network security analysts must verify that models make decisions based on
    defensible physical flow properties (e.g. byte volume, flag ratios) rather
    than spurious artifacts or hidden target leakage.

DCN / ML connection:
    Identifies whether an intrusion model relies primarily on volumetric features
    (e.g., flow_bytes_per_second during DoS) or stateful protocol features
    (e.g., syn_flag_count during port scans).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.pipeline import Pipeline


@dataclass
class GlobalFeatureImportance:
    """Container for global feature importance rankings."""
    method: str
    feature_importances: dict[str, float]  # Name -> score (0.0 to 1.0)
    top_features: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "feature_importances": {k: round(v, 4) for k, v in self.feature_importances.items()},
            "top_features": self.top_features,
            "description": self.description,
        }


def compute_global_importance(
    pipeline: Pipeline,
    X: pd.DataFrame,
    y: pd.Series | None = None,
    method: str = "auto",
    max_samples: int = 300,
    random_state: int = 42,
) -> GlobalFeatureImportance:
    """Compute global feature importance across input features.

    Args:
        pipeline: Fitted scikit-learn Pipeline.
        X: Feature DataFrame with column names.
        y: Ground truth labels (required for permutation importance).
        method: 'auto', 'tree_mdi', 'permutation', or 'coefficients'.
        max_samples: Subsample size for fast evaluation.
        random_state: Seed for permutation shuffling.

    Returns:
        GlobalFeatureImportance object.
    """
    feature_names = list(X.columns)
    model = pipeline.named_steps["model"]

    # 1. Tree-based MDI (Random Forest, Extra Trees, Decision Tree)
    if (method == "auto" or method == "tree_mdi") and hasattr(model, "feature_importances_"):
        raw_imp = model.feature_importances_
        # Normalize to sum to 1.0
        total = float(raw_imp.sum())
        norm_imp = raw_imp / total if total > 0 else raw_imp
        imp_dict = {name: float(norm_imp[i]) for i, name in enumerate(feature_names)}
        sorted_dict = dict(sorted(imp_dict.items(), key=lambda item: item[1], reverse=True))
        return GlobalFeatureImportance(
            method="Tree Mean Decrease in Impurity (Gini/Entropy MDI)",
            feature_importances=sorted_dict,
            top_features=list(sorted_dict.keys())[:5],
            description="Computed from total impurity reduction across all splits in tree ensembles.",
        )

    # 2. Linear model coefficients (Logistic Regression)
    if (method == "auto" or method == "coefficients") and hasattr(model, "coef_"):
        coefs = np.abs(model.coef_[0]) if model.coef_.ndim > 1 else np.abs(model.coef_)
        total = float(coefs.sum())
        norm_coefs = coefs / total if total > 0 else coefs
        imp_dict = {name: float(norm_coefs[i]) for i, name in enumerate(feature_names)}
        sorted_dict = dict(sorted(imp_dict.items(), key=lambda item: item[1], reverse=True))
        return GlobalFeatureImportance(
            method="Absolute Standardized Linear Coefficients",
            feature_importances=sorted_dict,
            top_features=list(sorted_dict.keys())[:5],
            description="Reflects the magnitude of the log-odds change contributed by each scaled feature.",
        )

    # 3. Model-agnostic Permutation Importance
    if y is not None:
        sub_X = X.iloc[:max_samples]
        sub_y = y.iloc[:max_samples]
        perm = permutation_importance(
            pipeline,
            sub_X,
            sub_y,
            scoring="f1_macro",
            n_repeats=3,
            random_state=random_state,
            n_jobs=-1,
        )
        raw_imp = np.maximum(perm.importances_mean, 0.0)
        total = float(raw_imp.sum())
        norm_imp = raw_imp / total if total > 0 else np.ones(len(feature_names)) / len(feature_names)
        imp_dict = {name: float(norm_imp[i]) for i, name in enumerate(feature_names)}
        sorted_dict = dict(sorted(imp_dict.items(), key=lambda item: item[1], reverse=True))
        return GlobalFeatureImportance(
            method="Model-Agnostic Permutation Importance",
            feature_importances=sorted_dict,
            top_features=list(sorted_dict.keys())[:5],
            description="Measures macro-F1 score drop when each feature is randomly shuffled.",
        )

    # Fallback: uniform
    uniform = {name: 1.0 / len(feature_names) for name in feature_names}
    return GlobalFeatureImportance(
        method="Uniform Baseline",
        feature_importances=uniform,
        top_features=feature_names[:5],
        description="Fallback ranking when feature importances cannot be directly extracted.",
    )
