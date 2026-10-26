"""Comprehensive Error Analysis and SHAP Explainability for NetSentry AI.

What it does:
    Rigorously dissects model misclassifications on holdout test partitions:
    - Segregates False Positives (benign flagged as threat) and False Negatives (threats missed).
    - Maps False Negatives to specific attack categories to expose family-specific vulnerabilities.
    - Profiles statistical feature distributions of error instances vs correct classifications.
    - Analyzes rare classes (N < 10) vulnerable to sample starvation.
    - Computes Shapley Additive exPlanations (SHAP) attributions using TreeExplainer.
    - Enforces academic rigor: feature importance and SHAP attributions reflect statistical
      correlations within the model manifold, NOT physical causality.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline


@dataclass
class ErrorAnalysisReport:
    """Structured forensic report on model errors and feature attributions."""
    total_evaluated_samples: int
    total_errors: int
    error_rate: float
    false_positives_count: int
    false_negatives_count: int
    false_negatives_by_family: dict[str, int]
    false_positives_profile: dict[str, dict[str, float]]
    false_negatives_profile: dict[str, dict[str, float]]
    rare_classes_analysis: list[dict[str, Any]]
    top_error_associated_features: list[dict[str, Any]]
    shap_attribution_summary: dict[str, float]
    causality_disclaimer: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_evaluated_samples": self.total_evaluated_samples,
            "total_errors": self.total_errors,
            "error_rate": round(self.error_rate, 4),
            "false_positives_count": self.false_positives_count,
            "false_negatives_count": self.false_negatives_count,
            "false_negatives_by_family": self.false_negatives_by_family,
            "false_positives_profile": self.false_positives_profile,
            "false_negatives_profile": self.false_negatives_profile,
            "rare_classes_analysis": self.rare_classes_analysis,
            "top_error_associated_features": self.top_error_associated_features,
            "shap_attribution_summary": {k: round(v, 4) for k, v in self.shap_attribution_summary.items()},
            "causality_disclaimer": self.causality_disclaimer,
        }


def perform_comprehensive_error_analysis(
    pipeline: Pipeline,
    X_test: pd.DataFrame,
    y_test: np.ndarray | pd.Series,
    original_labels: pd.Series | None = None,
    benign_label: str = "BENIGN",
    max_shap_samples: int = 150,
    random_state: int = 42,
) -> ErrorAnalysisReport:
    """Perform forensic error analysis and SHAP feature attribution on holdout test set.

    Args:
        pipeline: Fitted scikit-learn Pipeline with imputer, scaler, and estimator.
        X_test: Test features DataFrame.
        y_test: Ground truth binary labels (0 = Benign, 1 = Attack).
        original_labels: Multi-class labels for granular threat attribution.
        benign_label: String value for normal benign flows.
        max_shap_samples: Maximum instances to compute SHAP values (for latency control).
        random_state: Seed for sampling.

    Returns:
        ErrorAnalysisReport containing structured forensic findings.
    """
    clean_X = X_test.copy()
    features = list(clean_X.columns)
    y_arr = np.asarray(y_test)

    # 1. Generate predictions
    preds = pipeline.predict(clean_X)
    is_correct = preds == y_arr
    is_error = ~is_correct

    # Categorize error types
    is_fp = (preds == 1) & (y_arr == 0)
    is_fn = (preds == 0) & (y_arr == 1)
    is_tp = (preds == 1) & (y_arr == 1)
    is_tn = (preds == 0) & (y_arr == 0)

    fp_count = int(is_fp.sum())
    fn_count = int(is_fn.sum())
    total_samples = len(y_arr)
    total_errors = fp_count + fn_count
    error_rate = total_errors / max(total_samples, 1)

    # 2. Break down False Negatives by attack category
    fn_by_family: dict[str, int] = {}
    if original_labels is not None:
        fn_labels = original_labels.iloc[np.where(is_fn)[0]].astype(str)
        fn_by_family = {str(k): int(v) for k, v in fn_labels.value_counts().items()}

    # 3. Statistical profile of False Positives vs True Negatives
    fp_profile: dict[str, dict[str, float]] = {}
    if fp_count > 0 and is_tn.sum() > 0:
        fp_medians = clean_X.iloc[is_fp].median(numeric_only=True)
        tn_medians = clean_X.iloc[is_tn].median(numeric_only=True)
        for feat in features[:8]:  # Focus on key features
            fp_profile[feat] = {
                "fp_median": round(float(fp_medians.get(feat, 0.0)), 3),
                "tn_median": round(float(tn_medians.get(feat, 0.0)), 3),
            }

    # 4. Statistical profile of False Negatives vs True Positives
    fn_profile: dict[str, dict[str, float]] = {}
    if fn_count > 0 and is_tp.sum() > 0:
        fn_medians = clean_X.iloc[is_fn].median(numeric_only=True)
        tp_medians = clean_X.iloc[is_tp].median(numeric_only=True)
        for feat in features[:8]:
            fn_profile[feat] = {
                "fn_median": round(float(fn_medians.get(feat, 0.0)), 3),
                "tp_median": round(float(tp_medians.get(feat, 0.0)), 3),
            }

    # 5. Rare Class Sensitivity Analysis (N < 10)
    rare_analysis: list[dict[str, Any]] = []
    if original_labels is not None:
        class_counts = original_labels.value_counts()
        rare_classes = class_counts[class_counts < 10].index
        for r_cls in rare_classes:
            cls_mask = original_labels == r_cls
            cls_total = int(cls_mask.sum())
            cls_errors = int((is_error & cls_mask.to_numpy()).sum())
            cls_acc = 1.0 - (cls_errors / max(cls_total, 1))
            rare_analysis.append({
                "class_name": str(r_cls),
                "test_support": cls_total,
                "errors_count": cls_errors,
                "subset_accuracy": round(cls_acc, 4),
                "risk_comment": (
                    f"Severe sample starvation (N={cls_total}): metrics on this class have high statistical variance "
                    f"and cannot guarantee generalization in production."
                ),
            })

    # 6. Features most associated with errors (z-score divergence)
    error_features: list[dict[str, Any]] = []
    if total_errors > 0 and is_correct.sum() > 0:
        err_df = clean_X.iloc[is_error]
        corr_df = clean_X.iloc[is_correct]

        corr_mean = corr_df.mean(numeric_only=True)
        corr_std = corr_df.std(numeric_only=True).replace(0, 1.0).fillna(1.0)
        err_mean = err_df.mean(numeric_only=True)

        z_diffs = np.abs((err_mean - corr_mean) / corr_std).fillna(0.0)
        sorted_feats = z_diffs.sort_values(ascending=False).head(5)

        for feat_name, z_val in sorted_feats.items():
            error_features.append({
                "feature": str(feat_name),
                "z_score_deviation": round(float(z_val), 3),
                "interpretation": f"Error instances deviate by {z_val:.2f} standard deviations from correctly classified flows.",
            })

    # 7. SHAP Attribution Analysis
    shap_summary: dict[str, float] = {}
    try:
        import shap
        estimator = pipeline.named_steps["model"]
        
        # Transform data through pipeline preprocessing steps prior to model
        X_trans = clean_X.iloc[:max_shap_samples].copy()
        for step_name, transformer in pipeline.named_steps.items():
            if step_name != "model":
                X_trans = transformer.transform(X_trans)

        # Support TreeExplainer for tree ensembles (RandomForest, ExtraTrees, DecisionTree, LightGBM, XGBoost)
        is_tree = (
            hasattr(estimator, "estimators_")
            or hasattr(estimator, "tree_")
            or hasattr(estimator, "booster_")
            or hasattr(estimator, "get_booster")
            or "LGBM" in type(estimator).__name__
            or "XGB" in type(estimator).__name__
        )
        if is_tree:
            explainer = shap.TreeExplainer(estimator)
            shap_values = explainer.shap_values(X_trans)

            # If multi-output (binary classification), take positive class [1]
            if isinstance(shap_values, list) and len(shap_values) == 2:
                sv = shap_values[1]
            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
                sv = shap_values[:, :, 1]
            else:
                sv = shap_values

            mean_abs_shap = np.abs(sv).mean(axis=0)
            for i, feat in enumerate(features[:len(mean_abs_shap)]):
                shap_summary[feat] = float(mean_abs_shap[i])

            # Sort descending
            shap_summary = dict(sorted(shap_summary.items(), key=lambda x: x[1], reverse=True)[:10])
    except Exception:
        # Graceful fallback: model feature importances if SHAP encounters format differences
        estimator = pipeline.named_steps["model"]
        if hasattr(estimator, "feature_importances_"):
            raw_imp = estimator.feature_importances_
            for i, feat in enumerate(features[:len(raw_imp)]):
                shap_summary[feat] = float(raw_imp[i])
            shap_summary = dict(sorted(shap_summary.items(), key=lambda x: x[1], reverse=True)[:10])

    disclaimer = (
        "CRITICAL SCIENTIFIC PRINCIPLE: Feature attributions (including SHAP values and Tree MDI) "
        "measure statistical influence within the fitted model's decision manifold; they DO NOT "
        "demonstrate physical causality. An attacker can manipulate non-essential features "
        "(such as packet padding or artificial delays) without modifying the exploit payload. "
        "High feature importance must not be conflated with the root cause of an intrusion."
    )

    return ErrorAnalysisReport(
        total_evaluated_samples=total_samples,
        total_errors=total_errors,
        error_rate=error_rate,
        false_positives_count=fp_count,
        false_negatives_count=fn_count,
        false_negatives_by_family=fn_by_family,
        false_positives_profile=fp_profile,
        false_negatives_profile=fn_profile,
        rare_classes_analysis=rare_analysis,
        top_error_associated_features=error_features,
        shap_attribution_summary=shap_summary,
        causality_disclaimer=disclaimer,
    )
