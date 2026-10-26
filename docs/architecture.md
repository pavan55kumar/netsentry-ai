# NetSentry AI — System Architecture Guide

## 1. Executive Summary & Vision

**NetSentry AI** is an advanced network intrusion detection and anomaly research platform designed to bridge **Data Communication & Networking (DCN)** with **Machine Learning (ML)** engineering.

Rather than processing isolated packet bytes via expensive Deep Packet Inspection (which fails under modern TLS 1.3 encryption), NetSentry AI operates on **bidirectional network connection flows (NetFlow / IPFIX)**.

```
+---------------------------------------------------------------------------------------------------+
|                                  NETSENTRY AI ARCHITECTURE PIPELINE                              |
+---------------------------------------------------------------------------------------------------+
|  [Layer 1-4: Traffic Tap]                                                                         |
|       SPAN Port / PCAP Capture / CICFlowMeter                                                     |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Flow Aggregation Subsystem]                                                                     |
|       Canonical 5-Tuple Aggregation: (Src IP, Dst IP, Src Port, Dst Port, Protocol)                |
|       Bidirectional Flow Metrics (Duration, Packets, Bytes, Flag Counts, Rates)                   |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Leakage-Free Partitioning Subsystem]                                                            |
|       Target Leakage Detection & Auto-Pruning (IDs, Timestamps, Class Encodings)                  |
|       Audit Exact Feature Deduplication Policy                                                    |
|       Splitting: Stratified Random, Temporal Chronological, Group-Aware                           |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Model Training & Cross-Validation Engine]                                                       |
|       Pipelines with Train-Only Median Imputation & Robust / Standard Scaling                     |
|       Algorithms: LR, DT, RF, Extra Trees, HistGradientBoosting, KNN, Calibrated SVM, MLP, iForest|
|       RandomizedSearchCV Hyperparameter Tuning                                                    |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Evaluation & Security Telemetry]                                                                |
|       Macro-F1, PR-AUC, ROC-AUC, FPR, FNR, Per-Class Breakdown, Latency (ms), Footprint (KB)      |
|       Majority Baseline Evaluation (The Accuracy Trap)                                            |
|       Decision Threshold Calibration (Alert Fatigue Optimization)                                 |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Explainability & Research Layer]                                                                |
|       Global MDI / Permutation Feature Importance                                                 |
|       Local Instance Attributions & Plain-English Security Analyst Narratives                     |
|       Cross-Dataset Generalization & Covariate Model Drift Simulation                             |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Core Subsystems

### A. Data Ingestion & Validation (`src/netsentry/data/`)
- **`loader.py`**: Robust CSV loader with whitespace trimming, Latin-1 encoding fallbacks, and schema detection (`CIC-IDS2017`, `UNSW-NB15`, `NetSentry-Demo`).
- **`preprocessor.py`**: Performs automatic detection of target-leaking fields (`attack`, `label`, `outcome`, `flow id`, `timestamp`, `src ip`, `dst ip`). Handles division-by-zero infinite values by converting `np.inf` to `np.nan` prior to statistical imputation.
- **`splitting.py`**: Implements 3 partitioning strategies:
  1. **Stratified Holdout**: Preserves minority attack ratios across train and test sets.
  2. **Temporal Split**: Partitions records chronologically to evaluate generalization against future traffic.
  3. **Group Split**: Partitions sessions or hosts to prevent same-session records from contaminating test splits.

### B. Model Factory (`src/netsentry/models/`)
Wraps every algorithm in a self-contained scikit-learn `Pipeline`. Preprocessors are fitted *strictly* on training folds inside `cross_val_score`, completely eliminating preprocessing leakage.
- **Linear Baseline**: `LogisticRegression` with L2 penalty and balanced class weights.
- **Rule-Based**: `DecisionTreeClassifier` providing human-auditable if-then rules.
- **Bagging Ensembles**: `RandomForestClassifier` (500 trees) and `ExtraTreesClassifier` (500 trees).
- **Boosting**: `HistGradientBoostingClassifier` with max leaf nodes and L2 regularization.
- **Distance-Based**: `KNeighborsClassifier` with distance weighting and `RobustScaler`.
- **Maximum Margin**: `LinearSVC` wrapped in `CalibratedClassifierCV` for valid probability outputs.
- **Neural Network**: `MLPClassifier` with hidden layers `(64, 32)`, ReLU activations, and Adam optimizer.
- **Unsupervised Anomaly**: `IsolationForest` detecting outliers without requiring training labels.

### C. Evaluation & Thresholds (`src/netsentry/evaluation/`)
- Tracks both statistical effectiveness (`Macro-F1`, `PR-AUC`, `ROC-AUC`, `FPR`, `FNR`) and operational feasibility (`latency in ms/flow`, `serialized size in KB`).
- Evaluates against a `DummyClassifier` baseline to highlight the **Base Rate Fallacy / Accuracy Trap**.
- Calibrates decision thresholds on validation data to enforce strict false-positive rate constraints.

### D. Explainability (`src/netsentry/explainability/`)
- **Global**: Tree Mean Decrease in Impurity (MDI), Permutation Importance, and standardized linear coefficients.
- **Local**: Calculates feature deviation $z$-scores relative to normal baseline distributions.
- **Narrative**: Generates plain-English security analyst diagnoses detailing why a flow was flagged while disclosing probability calibration caveats and correlation vs causation distinctions.

### E. Advanced Research (`src/netsentry/research/`)
- **Cross-Dataset Domain Shift**: Standardizes heterogeneous schemas to common network flow features (`duration_sec`, `fwd_packets`, `bwd_packets`, `byte_rate`, `packet_rate`, `avg_packet_size`) to measure transfer degradation.
- **Zero-Day Anomaly Benchmark**: Benchmarks unsupervised `IsolationForest` against supervised models.
- **Model Drift Simulation**: Evaluates resilience under volumetric rate surges, protocol flag mutations, and Gaussian noise.
