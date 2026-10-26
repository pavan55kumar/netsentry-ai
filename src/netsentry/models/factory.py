"""Model factory and pipeline constructor for NetSentry AI.

What it does:
    Constructs leakage-free scikit-learn Pipelines for 9 distinct network intrusion
    algorithms across linear, tree, ensemble, distance, neural, and unsupervised families.

Why it is needed:
    Network traffic features exhibit extreme scale variations (e.g., flow duration in
    milliseconds vs TCP flag bit counts). Certain models (SVM, KNN, MLP, Logistic Regression)
    fail completely without scaling, whereas tree ensembles are invariant to monotonic scale.
    Wrapping preprocessing inside each pipeline guarantees that scalers and imputers are
    fitted strictly on training folds during cross-validation, preventing data leakage.

DCN / ML connection:
    - Logistic Regression / Linear SVM: High-throughput linear decision boundaries suitable for
      wire-speed hardware packet filtering.
    - Random Forest / Extra Trees: Resilient against noisy traffic bursts and multi-modal feature
      distributions.
    - Isolation Forest: Identifies novel zero-day attacks exhibiting unusual feature combinations
      without requiring prior labeled signatures.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier


@dataclass
class ModelSpec:
    """Descriptor containing model metadata, complexity, and tuning parameters."""
    key: str
    display_name: str
    family: str
    description: str
    complexity: str  # 'low', 'medium', 'high'
    is_unsupervised: bool = False
    param_grid: dict[str, list[Any]] = field(default_factory=dict)


BASE_MODELS = [
    "logistic_regression",
    "decision_tree",
    "random_forest_500",
    "extra_trees_500",
    "hist_gradient_boosting",
]

ADVANCED_MODELS = [
    "k_nearest_neighbors",
    "support_vector_machine",
    "mlp_neural_network",
    "isolation_forest",
]


def build_pipeline(model_key: str, random_state: int = 42, fast_mode: bool = False) -> Pipeline:
    """Create a self-contained, leakage-free Pipeline for the given algorithm.

    Args:
        model_key: Identifier for the algorithm.
        random_state: Seed for reproducibility.
        fast_mode: If True, uses reduced estimator counts for lightning-fast laptop runs.

    Returns:
        Configured sklearn Pipeline with appropriate imputation and scaling.
    """
    n_est = 100 if fast_mode else 300

    if model_key == "logistic_regression":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(
                max_iter=2500,
                class_weight="balanced",
                random_state=random_state,
                solver="lbfgs"
            )),
        ])

    elif model_key == "decision_tree":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", DecisionTreeClassifier(
                max_depth=12,
                min_samples_leaf=3,
                class_weight="balanced",
                random_state=random_state,
            )),
        ])

    elif model_key == "random_forest_500" or model_key == "random_forest":
        trees = 100 if fast_mode else 500
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(
                n_estimators=trees,
                min_samples_leaf=2,
                max_features="sqrt",
                class_weight="balanced",
                random_state=random_state,
                n_jobs=-1,
            )),
        ])

    elif model_key == "extra_trees_500" or model_key == "extra_trees":
        trees = 100 if fast_mode else 500
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", ExtraTreesClassifier(
                n_estimators=trees,
                min_samples_leaf=1,
                max_features="sqrt",
                class_weight="balanced",
                random_state=random_state,
                n_jobs=-1,
            )),
        ])

    elif model_key == "hist_gradient_boosting":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("model", HistGradientBoostingClassifier(
                learning_rate=0.08,
                max_leaf_nodes=31,
                l2_regularization=0.2,
                random_state=random_state,
            )),
        ])

    elif model_key == "k_nearest_neighbors":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", RobustScaler()),
            ("model", KNeighborsClassifier(n_neighbors=5, weights="distance", n_jobs=-1)),
        ])

    elif model_key == "support_vector_machine":
        # Calibrated LinearSVC provides fast convex optimization with valid probability output
        base_svc = LinearSVC(
            dual=False,
            max_iter=3000,
            class_weight="balanced",
            random_state=random_state,
        )
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("model", CalibratedClassifierCV(estimator=base_svc, cv=3)),
        ])

    elif model_key == "mlp_neural_network":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("model", MLPClassifier(
                hidden_layer_sizes=(64, 32),
                activation="relu",
                solver="adam",
                alpha=0.001,
                max_iter=150,
                early_stopping=True,
                random_state=random_state,
            )),
        ])

    elif model_key == "isolation_forest":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", RobustScaler()),
            ("model", IsolationForest(
                n_estimators=150,
                contamination=0.15,
                random_state=random_state,
                n_jobs=-1,
            )),
        ])

    else:
        raise ValueError(f"Unknown model key: '{model_key}'. Available: {list_available_keys()}")


def list_available_keys() -> list[str]:
    return BASE_MODELS + ADVANCED_MODELS


def get_available_models() -> dict[str, ModelSpec]:
    """Return dictionary of all supported model specifications and metadata."""
    return {
        "logistic_regression": ModelSpec(
            key="logistic_regression",
            display_name="Logistic Regression",
            family="Linear Baseline",
            description="Fast linear model with L2 regularization and balanced class weights. Interpretable baseline.",
            complexity="low",
            param_grid={
                "model__C": [0.01, 0.1, 1.0, 10.0],
                "model__penalty": ["l2"],
            },
        ),
        "decision_tree": ModelSpec(
            key="decision_tree",
            display_name="Decision Tree",
            family="Rule-Based Tree",
            description="Interpretable decision tree providing transparent if-then firewall rules.",
            complexity="low",
            param_grid={
                "model__max_depth": [6, 10, 15, None],
                "model__min_samples_split": [2, 5, 10],
                "model__criterion": ["gini", "entropy"],
            },
        ),
        "random_forest_500": ModelSpec(
            key="random_forest_500",
            display_name="Random Forest",
            family="Bagging Ensemble",
            description="Ensemble of de-correlated decision trees with bootstrap aggregation. Highly robust against noise.",
            complexity="medium",
            param_grid={
                "model__n_estimators": [100, 300, 500],
                "model__max_depth": [10, 20, None],
                "model__min_samples_leaf": [1, 2, 4],
            },
        ),
        "extra_trees_500": ModelSpec(
            key="extra_trees_500",
            display_name="Extra Trees",
            family="Extremely Randomized Trees",
            description="Ensemble of randomized cuts for reduced variance and faster tree construction.",
            complexity="medium",
            param_grid={
                "model__n_estimators": [100, 300, 500],
                "model__min_samples_leaf": [1, 2],
            },
        ),
        "hist_gradient_boosting": ModelSpec(
            key="hist_gradient_boosting",
            display_name="Histogram Gradient Boosting",
            family="Boosting Ensemble",
            description="Binned histogram gradient booster. Fast training on tabular network flow datasets.",
            complexity="medium",
            param_grid={
                "model__learning_rate": [0.03, 0.08, 0.15],
                "model__max_leaf_nodes": [15, 31, 63],
                "model__l2_regularization": [0.0, 0.2, 1.0],
            },
        ),
        "k_nearest_neighbors": ModelSpec(
            key="k_nearest_neighbors",
            display_name="K-Nearest Neighbors",
            family="Instance-Based",
            description="Non-parametric classifier assigning labels based on Euclidean proximity in flow space.",
            complexity="medium",
            param_grid={
                "model__n_neighbors": [3, 5, 9, 15],
                "model__weights": ["uniform", "distance"],
            },
        ),
        "support_vector_machine": ModelSpec(
            key="support_vector_machine",
            display_name="Support Vector Machine (Calibrated)",
            family="Maximum Margin Classifier",
            description="Finds optimal separating hyperplanes between benign and malicious flows with Platt probability calibration.",
            complexity="medium",
            param_grid={
                "model__estimator__C": [0.1, 1.0, 5.0],
            },
        ),
        "mlp_neural_network": ModelSpec(
            key="mlp_neural_network",
            display_name="MLP Neural Network",
            family="Deep Learning / Neural",
            description="Feed-forward artificial neural network with ReLU activations and Adam optimization.",
            complexity="high",
            param_grid={
                "model__hidden_layer_sizes": [(32,), (64, 32), (128, 64)],
                "model__alpha": [0.0001, 0.001, 0.01],
            },
        ),
        "isolation_forest": ModelSpec(
            key="isolation_forest",
            display_name="Isolation Forest",
            family="Unsupervised Anomaly Detector",
            description="Isolates anomalous network flows by recursively partitioning feature values without requiring attack labels.",
            complexity="medium",
            is_unsupervised=True,
            param_grid={
                "model__n_estimators": [100, 200],
                "model__contamination": [0.05, 0.10, 0.20],
            },
        ),
    }
