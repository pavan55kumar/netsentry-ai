"""Modular multi-model training and cross-validation pipeline for NetSentry AI.

What it does:
    Orchestrates the training, cross-validation, holdout evaluation, comparison,
    and artifact serialization of multiple network intrusion detection algorithms.

Why it is needed:
    Enforces the core scientific rule: holdout test sets must remain genuinely untouched
    during model selection. Preprocessing, scaling, and hyperparameter tuning occur strictly
    within training cross-validation folds, preventing data leakage.

DCN / ML connection:
    Different models present stark operational trade-offs: Random Forests offer superior
    recall on complex multi-flow attacks, whereas Logistic Regression and Decision Trees
    achieve sub-millisecond wire-speed latency required for line-rate packet inspection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import time
from typing import Any, Callable, Sequence

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline

from ..data.preprocessor import PreparedData
from ..evaluation.metrics import (
    ModelMetrics,
    calculate_inference_latency,
    evaluate_predictions,
    measure_model_size_kb,
)
from ..evaluation.baseline import evaluate_majority_baseline
from ..models.factory import BASE_MODELS, build_pipeline, get_available_models
from .tracker import ExperimentRecord, ExperimentTracker
from .tuning import tune_hyperparameters


@dataclass
class ModelResult:
    """Evaluation output for a single candidate algorithm."""
    name: str
    display_name: str
    pipeline: Pipeline
    cv_macro_f1_mean: float
    cv_macro_f1_std: float
    holdout_metrics: ModelMetrics
    is_tuned: bool = False
    tuning_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrainingRunResult:
    """Complete summary of a multi-model training and evaluation experiment."""
    champion_model_name: str
    champion_pipeline: Pipeline
    model_results: dict[str, ModelResult]
    baseline_summary: dict[str, Any]
    artifacts_dir: Path
    prepared_data: PreparedData
    comparison_table: pd.DataFrame
    run_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "selected_model": self.champion_model_name,
            "selection_rule": "Highest mean training-only cross-validation macro-F1",
            "rows_train": len(self.prepared_data.X_train),
            "rows_test": len(self.prepared_data.X_test),
            "feature_names": self.prepared_data.feature_names,
            "notes": self.prepared_data.notes,
            "baseline": self.baseline_summary,
            "models": {
                name: {
                    "display_name": res.display_name,
                    "cv_macro_f1_mean": round(res.cv_macro_f1_mean, 4),
                    "cv_macro_f1_std": round(res.cv_macro_f1_std, 4),
                    "holdout_metrics": res.holdout_metrics.to_dict(),
                    "is_tuned": res.is_tuned,
                }
                for name, res in self.model_results.items()
            },
        }


def train_and_evaluate_models(
    prepared: PreparedData,
    model_keys: Sequence[str] = BASE_MODELS,
    cv_folds: int = 5,
    random_state: int = 42,
    artifacts_dir: str | Path = "artifacts",
    tune_models: bool = False,
    fast_mode: bool = False,
    progress_callback: Callable[[str, float], None] | None = None,
) -> TrainingRunResult:
    """Execute leakage-aware training, cross-validation, and holdout testing.

    Args:
        prepared: Validated and partitioned PreparedData.
        model_keys: List of model identifiers to train.
        cv_folds: Cross-validation splits on training data only (>= 2).
        random_state: Seed for reproducibility.
        artifacts_dir: Directory where model artifacts and reports are saved.
        tune_models: Whether to run RandomizedSearchCV hyperparameter tuning.
        fast_mode: If True, uses reduced estimator sizes for fast laptop experimentation.
        progress_callback: Optional status hook for web UI progress bars.

    Returns:
        TrainingRunResult object containing all metrics, fitted pipelines, and comparison tables.
    """
    if cv_folds < 2:
        raise ValueError("cv_folds must be at least 2")

    out_dir = Path(artifacts_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "feature_names.json").write_text(
        json.dumps(prepared.feature_names, indent=2), encoding="utf-8"
    )

    models_info = get_available_models()
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)

    results: dict[str, ModelResult] = {}
    total_models = len(model_keys)

    for idx, key in enumerate(model_keys):
        if key not in models_info:
            continue
        spec = models_info[key]
        display_name = spec.display_name

        if progress_callback:
            progress_callback(f"Training and validating {display_name}...", idx / max(total_models, 1))

        # Check if unsupervised anomaly detector
        if spec.is_unsupervised:
            pipe = build_pipeline(key, random_state=random_state, fast_mode=fast_mode)
            start_fit = time.perf_counter()
            pipe.fit(prepared.X_train)
            train_duration = time.perf_counter() - start_fit

            # Isolation forest predicts -1 for anomalies, 1 for normal
            raw_preds = pipe.predict(prepared.X_test)
            preds = np.where(raw_preds == -1, 1, 0)
            # Anomaly score: lower score = more anomalous. Negate for malicious probability proxy
            raw_scores = pipe.named_steps["model"].decision_function(
                pipe.named_steps["scaler"].transform(
                    pipe.named_steps["imputer"].transform(prepared.X_test)
                )
            )
            # Invert and normalize to [0, 1]
            min_s, max_s = raw_scores.min(), raw_scores.max()
            norm_scores = 1.0 - ((raw_scores - min_s) / max(max_s - min_s, 1e-6))
            probs = np.column_stack([1.0 - norm_scores, norm_scores])

            latency = calculate_inference_latency(pipe, prepared.X_test)
            size_kb = measure_model_size_kb(pipe)
            holdout_metrics = evaluate_predictions(
                prepared.y_test,
                preds,
                y_proba=probs,
                target_names=prepared.target_names,
                training_duration_sec=train_duration,
                inference_latency_ms=latency,
                model_size_kb=size_kb,
            )

            results[key] = ModelResult(
                name=key,
                display_name=display_name,
                pipeline=pipe,
                cv_macro_f1_mean=holdout_metrics.f1_macro,  # Unsupervised fallback
                cv_macro_f1_std=0.0,
                holdout_metrics=holdout_metrics,
            )
            continue

        # Supervised Pipeline
        if tune_models and spec.param_grid:
            pipe, tune_summary = tune_hyperparameters(
                key, prepared.X_train, prepared.y_train, cv_folds=min(cv_folds, 3), random_state=random_state
            )
            is_tuned = True
            cv_mean = tune_summary.get("best_cv_macro_f1", 0.0)
            cv_std = 0.0
            train_duration = tune_summary.get("tuning_duration_sec", 0.0)
        else:
            pipe = build_pipeline(key, random_state=random_state, fast_mode=fast_mode)
            is_tuned = False
            tune_summary = {}
            # Evaluate CV macro-F1 strictly on training data
            scores = cross_val_score(
                pipe,
                prepared.X_train,
                prepared.y_train,
                cv=cv,
                scoring="f1_macro",
                n_jobs=-1,
            )
            cv_mean = float(scores.mean())
            cv_std = float(scores.std())

            start_fit = time.perf_counter()
            pipe.fit(prepared.X_train, prepared.y_train)
            train_duration = time.perf_counter() - start_fit

        # Measure inference latency and size
        latency = calculate_inference_latency(pipe, prepared.X_test)
        size_kb = measure_model_size_kb(pipe)

        # Holdout predictions
        holdout_preds = pipe.predict(prepared.X_test)
        holdout_proba = pipe.predict_proba(prepared.X_test) if hasattr(pipe, "predict_proba") else None

        holdout_metrics = evaluate_predictions(
            prepared.y_test,
            holdout_preds,
            y_proba=holdout_proba,
            target_names=prepared.target_names,
            training_duration_sec=train_duration,
            inference_latency_ms=latency,
            model_size_kb=size_kb,
        )

        results[key] = ModelResult(
            name=key,
            display_name=display_name,
            pipeline=pipe,
            cv_macro_f1_mean=cv_mean,
            cv_macro_f1_std=cv_std,
            holdout_metrics=holdout_metrics,
            is_tuned=is_tuned,
            tuning_info=tune_summary,
        )

    if progress_callback:
        progress_callback("Selecting champion model and generating reports...", 0.95)

    # Champion selection: based strictly on mean training CV macro-F1
    best_name = max(results, key=lambda n: results[n].cv_macro_f1_mean)
    champion_pipe = results[best_name].pipeline
    joblib.dump(champion_pipe, out_dir / "best_model.joblib")

    # Baseline comparison (Accuracy Trap)
    baseline_info = evaluate_majority_baseline(
        prepared.y_train, prepared.y_test, target_names=prepared.target_names
    )

    # Comparison DataFrame
    comp_rows = {}
    for name, res in results.items():
        hm = res.holdout_metrics
        comp_rows[res.display_name] = {
            "Model Key": name,
            "CV Macro-F1": f"{res.cv_macro_f1_mean:.3f} (+/- {res.cv_macro_f1_std:.3f})",
            "Holdout Accuracy": hm.accuracy,
            "Holdout Macro-F1": hm.f1_macro,
            "Holdout Weighted-F1": hm.f1_weighted,
            "Precision (Malicious)": hm.precision_malicious,
            "Recall (Malicious)": hm.recall_malicious,
            "False Positive Rate": hm.false_positive_rate,
            "ROC-AUC": hm.roc_auc if hm.roc_auc is not None else "N/A",
            "PR-AUC": hm.pr_auc if hm.pr_auc is not None else "N/A",
            "Latency (ms/sample)": hm.inference_latency_ms,
            "Model Size (KB)": hm.model_size_kb,
            "Train Time (s)": hm.training_duration_sec,
        }
    comparison_df = pd.DataFrame(comp_rows).T
    comparison_df.to_csv(out_dir / "model_comparison.csv")

    # Confusion matrix plot for champion
    best_matrix = np.asarray(results[best_name].holdout_metrics.confusion_matrix)
    labels = prepared.target_names if prepared.target_names and len(prepared.target_names) == len(best_matrix) else None
    display = ConfusionMatrixDisplay(confusion_matrix=best_matrix, display_labels=labels)
    fig, ax = plt.subplots(figsize=(6, 5))
    display.plot(cmap="Blues", values_format="d", ax=ax)
    plt.title(f"Holdout Confusion Matrix: {results[best_name].display_name}", fontsize=11)
    plt.tight_layout()
    plt.savefig(out_dir / "confusion_matrix.png", dpi=160)
    plt.close()

    run_id = ExperimentTracker.create_run_id()
    run_result = TrainingRunResult(
        champion_model_name=best_name,
        champion_pipeline=champion_pipe,
        model_results=results,
        baseline_summary=baseline_info,
        artifacts_dir=out_dir,
        prepared_data=prepared,
        comparison_table=comparison_df,
        run_id=run_id,
    )

    # Save metrics.json
    (out_dir / "metrics.json").write_text(
        json.dumps(run_result.to_dict(), indent=2), encoding="utf-8"
    )

    # Register in ExperimentTracker
    tracker = ExperimentTracker()
    record = ExperimentRecord(
        run_id=run_id,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        dataset_name=str(prepared.notes[0]) if prepared.notes else "custom",
        rows_train=len(prepared.X_train),
        rows_test=len(prepared.X_test),
        features_count=len(prepared.feature_names),
        feature_names=prepared.feature_names,
        split_strategy=str(prepared.notes[-1]) if prepared.notes else "stratified",
        models_evaluated=list(results.keys()),
        champion_model=best_name,
        selection_metric="CV Macro-F1",
        champion_metrics=results[best_name].holdout_metrics.to_dict(),
        all_models_summary={
            name: {
                "cv_macro_f1": res.cv_macro_f1_mean,
                "accuracy": res.holdout_metrics.accuracy,
                "f1_macro": res.holdout_metrics.f1_macro,
                "fpr": res.holdout_metrics.false_positive_rate,
            }
            for name, res in results.items()
        },
        notes=prepared.notes,
        artifacts_dir=str(out_dir.resolve()),
    )
    tracker.log_run(record)

    if progress_callback:
        progress_callback("Training complete! Champion model saved.", 1.0)

    return run_result
