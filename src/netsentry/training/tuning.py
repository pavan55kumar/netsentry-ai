"""Leakage-free hyperparameter optimization for NetSentry AI models.

What it does:
    Performs randomized hyperparameter search over pipeline parameter spaces
    exclusively on the training partition using cross-validation.

Why it is needed:
    Default model parameters (e.g. tree depth, regularization penalty C) are rarely
    optimal for specific network traffic topologies. Tuning on training folds improves
    generalization without leaking test set performance.

DCN / ML connection:
    Over-regularized models under-fit complex attack signatures, while unconstrained
    decision trees memorize specific port numbers and over-fit training capture sessions.
"""
from __future__ import annotations

import time
from typing import Any
import pandas as pd
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline

from ..models.factory import build_pipeline, get_available_models


def tune_hyperparameters(
    model_key: str,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    cv_folds: int = 3,
    n_iter: int = 6,
    random_state: int = 42,
) -> tuple[Pipeline, dict[str, Any]]:
    """Tune pipeline hyperparameters using RandomizedSearchCV on training folds.

    Args:
        model_key: Model key from registry.
        X_train: Training features.
        y_train: Training labels.
        cv_folds: Number of inner CV folds (default 3).
        n_iter: Number of parameter combinations to sample.
        random_state: Random seed.

    Returns:
        (best_fitted_pipeline, tuning_summary_dict)
    """
    models = get_available_models()
    if model_key not in models:
        raise ValueError(f"Unknown model key for tuning: '{model_key}'")

    spec = models[model_key]
    if not spec.param_grid:
        # No grid defined, return standard fit
        pipeline = build_pipeline(model_key, random_state=random_state)
        pipeline.fit(X_train, y_train)
        return pipeline, {"tuned": False, "reason": "No hyperparameter grid defined"}

    base_pipe = build_pipeline(model_key, random_state=random_state)
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)

    start_time = time.perf_counter()
    search = RandomizedSearchCV(
        estimator=base_pipe,
        param_distributions=spec.param_grid,
        n_iter=min(n_iter, 10),
        cv=cv,
        scoring="f1_macro",
        random_state=random_state,
        n_jobs=-1,
        refit=True,
    )

    search.fit(X_train, y_train)
    duration = time.perf_counter() - start_time

    best_pipeline = search.best_estimator_
    summary = {
        "tuned": True,
        "best_params": search.best_params_,
        "best_cv_macro_f1": float(search.best_score_),
        "tuning_duration_sec": round(duration, 3),
        "total_combinations_tested": min(n_iter, len(search.cv_results_["params"])),
    }
    return best_pipeline, summary
