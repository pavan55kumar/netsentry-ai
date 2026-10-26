"""Train leakage-aware NetSentry AI models and select using training-only cross-validation.

Supports educational baseline runs, multi-model benchmarking, hyperparameter tuning,
and production-grade artifact export.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from sklearn.pipeline import Pipeline

from .data import load_csv, make_demo_dataset, prepare_data, PreparedData
from .evaluation.metrics import metrics_for_backward_compat as metrics_for
from .models.factory import BASE_MODELS, ADVANCED_MODELS, build_pipeline
from .training.pipeline import train_and_evaluate_models


def model_candidates(random_state: int) -> dict[str, Pipeline]:
    """Backward-compatible model candidates for tabular flow measurements."""
    return {
        "logistic_regression": build_pipeline("logistic_regression", random_state),
        "random_forest_500": build_pipeline("random_forest_500", random_state),
        "extra_trees_500": build_pipeline("extra_trees_500", random_state),
        "hist_gradient_boosting": build_pipeline("hist_gradient_boosting", random_state),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--demo", action="store_true", help="Use included synthetic data.")
    source.add_argument("--data", help="Path to a real, labeled network-flow CSV.")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--positive-label", help="Exact target value meaning malicious.")
    parser.add_argument("--drop-columns", nargs="*", default=[], help="Extra fields to exclude, e.g. Flow_ID Timestamp.")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--cv-folds", type=int, default=5, help="Cross-validation folds used only on training data.")
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--models", nargs="*", default=BASE_MODELS, help="Model keys to train.")
    parser.add_argument("--tune", action="store_true", help="Enable RandomizedSearchCV hyperparameter tuning.")
    parser.add_argument("--fast", action="store_true", help="Fast training mode with reduced estimator count.")
    parser.add_argument("--multiclass", action="store_true", help="Preserve multi-class target categories.")
    parser.add_argument("--split-strategy", default="stratified", choices=["stratified", "temporal", "group"])
    parser.add_argument("--time-column", help="Timestamp column for temporal splitting.")
    parser.add_argument("--group-column", help="Session or host column for group splitting.")
    args = parser.parse_args()

    if args.cv_folds < 2:
        raise ValueError("--cv-folds must be at least 2")

    frame = make_demo_dataset(random_state=args.random_state) if args.demo else load_csv(args.data)
    prepared = prepare_data(
        frame=frame,
        label_column=args.label_column,
        test_size=args.test_size,
        random_state=args.random_state,
        positive_label=args.positive_label,
        extra_drop_columns=args.drop_columns,
        multiclass=args.multiclass,
        split_strategy=args.split_strategy,
        time_column=args.time_column,
        group_column=args.group_column,
    )

    print(f"[*] Prepared {len(prepared.X_train)} training flows, {len(prepared.X_test)} holdout test flows.")
    print(f"[*] Features ({len(prepared.feature_names)}): {prepared.feature_names}")
    for note in prepared.notes:
        print(f"    - {note}")

    result = train_and_evaluate_models(
        prepared=prepared,
        model_keys=args.models,
        cv_folds=args.cv_folds,
        random_state=args.random_state,
        artifacts_dir=args.artifacts_dir,
        tune_models=args.tune,
        fast_mode=args.fast,
    )

    for name, m_res in result.model_results.items():
        hm = m_res.holdout_metrics
        print(
            f"{name}: CV macro-F1={m_res.cv_macro_f1_mean:.3f} (+/- {m_res.cv_macro_f1_std:.3f}); "
            f"holdout accuracy={hm.accuracy:.3f}; FPR={hm.false_positive_rate:.3f}; latency={hm.inference_latency_ms:.3f}ms"
        )

    print(f"\n[+] Champion model selected: {result.champion_model_name}")
    print(f"[+] Saved model artifacts and reports to {Path(args.artifacts_dir).resolve()}")


if __name__ == "__main__":
    main()
