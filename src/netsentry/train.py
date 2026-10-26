"""Train leakage-aware NetSentry AI models and select using training-only cross-validation."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import ConfusionMatrixDisplay, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .data import load_csv, make_demo_dataset, prepare_data


def model_candidates(random_state: int) -> dict[str, Pipeline]:
    """Reasonable, dependency-free model candidates for tabular flow measurements."""
    return {
        "logistic_regression": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
            ("model", LogisticRegression(max_iter=3000, class_weight="balanced", random_state=random_state)),
        ]),
        "random_forest_500": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(n_estimators=500, min_samples_leaf=2, max_features="sqrt", class_weight="balanced", random_state=random_state, n_jobs=-1)),
        ]),
        "extra_trees_500": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", ExtraTreesClassifier(n_estimators=500, min_samples_leaf=1, max_features="sqrt", class_weight="balanced", random_state=random_state, n_jobs=-1)),
        ]),
        "hist_gradient_boosting": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", HistGradientBoostingClassifier(learning_rate=0.08, max_leaf_nodes=15, l2_regularization=0.2, random_state=random_state)),
        ]),
    }


def metrics_for(y_true, y_pred) -> tuple[dict[str, float], list[list[int]]]:
    precision, recall, _, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    _, _, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "accuracy": float((tn + tp) / cm.sum()),
        "precision_malicious": float(precision), "recall_malicious": float(recall),
        "macro_f1": float(macro_f1),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "true_negatives": int(tn), "false_positives": int(fp),
        "false_negatives": int(fn), "true_positives": int(tp),
    }, cm.tolist()


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
    args = parser.parse_args()
    if args.cv_folds < 2:
        raise ValueError("--cv-folds must be at least 2")

    frame = make_demo_dataset(random_state=args.random_state) if args.demo else load_csv(args.data)
    prepared = prepare_data(frame, args.label_column, args.test_size, args.random_state, args.positive_label, args.drop_columns)
    output = Path(args.artifacts_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "feature_names.json").write_text(json.dumps(prepared.feature_names, indent=2), encoding="utf-8")

    # The test set remains untouched during selection. Pipelines fit imputation/scaling
    # inside each cross-validation fold, preventing preprocessing leakage.
    cv = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=args.random_state)
    results: dict[str, dict] = {}
    fitted: dict[str, Pipeline] = {}
    for name, model in model_candidates(args.random_state).items():
        scores = cross_val_score(model, prepared.X_train, prepared.y_train, cv=cv, scoring="f1_macro", n_jobs=1)
        model.fit(prepared.X_train, prepared.y_train)
        values, matrix = metrics_for(prepared.y_test, model.predict(prepared.X_test))
        results[name] = {
            "cv_macro_f1_mean": float(scores.mean()), "cv_macro_f1_std": float(scores.std()),
            "holdout_metrics": values, "holdout_confusion_matrix": matrix,
        }
        fitted[name] = model
        print(f"{name}: CV macro-F1={scores.mean():.3f} (+/- {scores.std():.3f}); holdout accuracy={values['accuracy']:.3f}")

    # Select only with CV results; holdout metrics are reported once as an honest final check.
    best_name = max(results, key=lambda n: results[n]["cv_macro_f1_mean"])
    joblib.dump(fitted[best_name], output / "best_model.joblib")
    report = {
        "selected_model": best_name,
        "selection_rule": "Highest mean 5-fold training-only cross-validation macro-F1.",
        "data_source": "synthetic demo" if args.demo else str(Path(args.data).resolve()),
        "rows_train": len(prepared.X_train), "rows_test": len(prepared.X_test),
        "notes": prepared.notes,
        "models": results,
    }
    (output / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    comparison = pd.DataFrame({
        name: {"cv_macro_f1_mean": item["cv_macro_f1_mean"], "cv_macro_f1_std": item["cv_macro_f1_std"], **item["holdout_metrics"]}
        for name, item in results.items()
    }).T
    comparison.to_csv(output / "model_comparison.csv")
    matrix = np.asarray(results[best_name]["holdout_confusion_matrix"])
    display = ConfusionMatrixDisplay(confusion_matrix=matrix, display_labels=["benign", "malicious"])
    display.plot(cmap="Blues", values_format="d")
    plt.title(f"Final holdout confusion matrix: {best_name}")
    plt.tight_layout()
    plt.savefig(output / "confusion_matrix.png", dpi=160)
    print(f"Saved {best_name} and reports to {output.resolve()}")


if __name__ == "__main__":
    main()
