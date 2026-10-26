# NetSentry AI — Model Training & Tuning Guide

## 1. Quick Start Commands

### A. Run Baseline Demo (Synthetic Educational Data)
```powershell
python -m netsentry.train --demo
```
Generates 1,200 synthetic network flows, trains 4 core baseline models with 5-fold cross-validation, and saves champion artifacts to `artifacts/`.

### B. Fast Laptop Mode (Sub-second execution)
```powershell
python -m netsentry.train --demo --fast
```
Reduces ensemble tree counts from 500 to 100 for rapid iteration on student laptops without fan spin-up.

### C. Train All 9 Supported Algorithms
```powershell
python -m netsentry.train --demo --fast --models logistic_regression decision_tree random_forest_500 extra_trees_500 hist_gradient_boosting k_nearest_neighbors support_vector_machine mlp_neural_network isolation_forest
```

### D. Hyperparameter Optimization on Training Folds
```powershell
python -m netsentry.train --demo --tune --fast
```
Executes `RandomizedSearchCV` exclusively on training folds to discover optimal tree depths, leaf nodes, and regularization penalties.

### E. Train on Real Research Dataset (CIC-IDS2017 Sample)
```powershell
python -m netsentry.train --data data\sample\cicids2017_sample.csv --label-column Label --positive-label "DoS Hulk" --fast --artifacts-dir artifacts\cicids_run
```

---

## 2. Supported Algorithms & Operational Trade-offs

| Key | Model Name | Family | Computational Latency | Best Suited For |
| :--- | :--- | :--- | :--- | :--- |
| `logistic_regression` | Logistic Regression | Linear | Sub-millisecond (~0.01 ms) | High-throughput line-rate hardware packet filtering. |
| `decision_tree` | Decision Tree | Rule-Based | Sub-millisecond (~0.01 ms) | Interpretable if-then rules for firewall translation. |
| `random_forest_500` | Random Forest | Bagging Ensemble | Low-medium (~0.15 ms) | Complex multi-feature attack signatures; robust against noise. |
| `extra_trees_500` | Extra Trees | Randomized Ensemble| Low-medium (~0.12 ms) | Extremely randomized cuts; lowest variance on flow measurements. |
| `hist_gradient_boosting` | Hist Gradient Boosting | Boosting Ensemble | Fast (~0.02 ms) | Tabular flow datasets with binned numeric continuous values. |
| `k_nearest_neighbors` | K-Nearest Neighbors | Instance-Based | Medium (~0.30 ms) | Non-parametric proximity baseline in normalized flow space. |
| `support_vector_machine` | Calibrated Linear SVM | Maximum Margin | Fast (~0.02 ms) | Linear hyperplanes with Platt probability calibration. |
| `mlp_neural_network` | MLP Neural Network | Deep Learning | Medium (~0.10 ms) | Non-linear interaction between complex packet metrics. |
| `isolation_forest` | Isolation Forest | Unsupervised | Fast (~0.05 ms) | Zero-day anomaly discovery without prior attack labels. |

---

## 3. Leakage Guardrails Enforced

1. **Preprocessing Pipeline Isolation:** All scalers (`StandardScaler`, `RobustScaler`) and imputers (`SimpleImputer`) are chained within scikit-learn `Pipeline` objects. When 5-fold cross-validation executes, statistics (medians, means, standard deviations) are computed solely from the 4 training folds and applied to the 5th validation fold.
2. **Untouched Test Holdout:** The holdout split (default 25%) is isolated before cross-validation begins and is evaluated exactly once after the champion model is selected.
3. **Automatic Leakage Detection:** Columns matching `flow id`, `timestamp`, `src ip`, `dst ip`, `attack`, `class`, or `label` are automatically identified and excluded from the feature matrix $X$.
4. **Duplicate Record Audit:** Identical feature vectors are audited prior to partitioning to prevent identical connection records from co-occurring in both train and test splits.
