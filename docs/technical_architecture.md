# NetSentry AI — Technical Architecture Specification

## 1. Executive Summary & Vision

**NetSentry AI** is an advanced, production-grade Network Intrusion Detection System (NIDS) and research experimentation platform designed to bridge **Data Communication & Networking (DCN)** with **Machine Learning (ML)** engineering.

Traditional intrusion detection systems rely either on brittle, manual regular-expression signatures (e.g. Snort rules) or expensive Deep Packet Inspection (DPI). Under modern transport protocols (TLS 1.3, QUIC, WireGuard, HTTPS), packet payloads are completely encrypted with authenticated encryption (AEAD ciphers), rendering payload-based inspection blind.

NetSentry AI solves this paradigm shift by operating strictly on **bidirectional network connection flows (NetFlow / IPFIX telemetry)**. By analyzing temporal, statistical, and volumetric connection behaviors (flow duration, inter-arrival times, packet distributions, TCP control flags, and transmission rates), NetSentry AI detects sophisticated network attacks (DDoS, Botnets, Port Scans, Brute Force, Exploits) at line rate without decrypting confidential user payloads.

---

## 2. End-to-End System Architecture

```
+---------------------------------------------------------------------------------------------------+
|                                  NETSENTRY AI ARCHITECTURE PIPELINE                              |
+---------------------------------------------------------------------------------------------------+
|  [Network Layer & Tap]                                                                            |
|       Network Interface / SPAN Mirror Port / PCAP File Capture                                   |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Bidirectional Flow Extraction Subsystem] (netsentry.pcap.flow_extractor)                         |
|       • Canonical 5-Tuple Aggregation: min((SrcIP, SrcPort), (DstIP, DstPort)) + Protocol        |
|       • Forward (Client->Server) & Backward (Server->Client) Metric Derivations                   |
|       • Timing: Duration, Inter-Arrival Times (IAT Mean, Std, Max, Min)                          |
|       • Volumetrics: Flow Bytes/s, Flow Packets/s, Packet Length Statistics                       |
|       • Transport Flags: SYN, RST, FIN, ACK, PSH, URG, ECE, CWE Counters                         |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Leakage-Free Partitioning & Preprocessing Engine] (netsentry.data)                              |
|       • Target Leakage Sentinel: Automatic elimination of surrogate labels, timestamps & IDs     |
|       • Deduplication Policy: Audit exact duplicates and flag cross-split contamination           |
|       • Partitioning: Stratified Holdout, Temporal Chronological, Group-Aware                     |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Multi-Model Pipeline Architecture] (netsentry.models.factory & netsentry.training)              |
|       • Independent Pipelines: Imputation + Scaling strictly inside cross-validation folds      |
|       • 11 Algorithms across 6 Distinct Machine Learning Paradigms:                               |
|           - Linear Baselines: Logistic Regression, Calibrated Linear SVM                          |
|           - Decision Trees & Rule Extraction: Decision Tree (CART)                                |
|           - Bagging Ensembles: Random Forest, Extremely Randomized Trees (Extra Trees)            |
|           - Histogram & Gradient Boosters: HistGradientBoosting, LightGBM, XGBoost               |
|           - Distance & Geometric: K-Nearest Neighbors (RobustScaler)                              |
|           - Deep Neural Networks: Multi-Layer Perceptron (MLP, Adam, ReLU)                        |
|           - Unsupervised Anomaly Detection: Isolation Forest                                      |
|       • Hyperparameter Optimization: RandomizedSearchCV on Training Folds Only                    |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Scientific Evaluation & Operational Telemetry] (netsentry.evaluation)                           |
|       • Metric Suite: Macro-F1, Weighted-F1, Precision, Recall, FPR, FNR, ROC-AUC, PR-AUC         |
|       • Majority Baseline Benchmark (The Accuracy Trap)                                           |
|       • Decision Threshold Sweeper: Alert fatigue optimization for target FPR limits (<1.0%)      |
|       • Inference Profiler: Sub-millisecond latency per flow & serialized model footprint (KB)   |
|                           │                                                                       |
|                           ▼                                                                       |
|  [Explainability & Research Workbench] (netsentry.explainability & netsentry.research)            |
|       • Global Explainability: Mean Decrease in Impurity (MDI) & Permutation Feature Importance   |
|       • Local Explainability: Feature z-score deviation vs normal baseline traffic                |
|       • Plain-English Security Narratives: Automated SOC incident diagnostic reports              |
|       • Experiment A: Cross-Dataset Domain Shift (CIC-IDS2017 <-> UNSW-NB15)                      |
|       • Experiment B: Unseen Zero-Day Attack Discovery (Class Holdouts)                           |
|       • Experiment C: Network Traffic Covariate Drift Simulation (Bandwidth, Jitter, Flags)       |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Subsystem Breakdown

### 3.1. Flow Ingestion & 5-Tuple Reconstruction (`netsentry.pcap`)
Raw Ethernet frames arrive at the network sensor. NetSentry aggregates raw frames into bidirectional flows using the canonical 5-tuple:
$$\text{Flow Key} = (\min(IP_{src}:Port_{src}, IP_{dst}:Port_{dst}), \max(IP_{src}:Port_{src}, IP_{dst}:Port_{dst}), \text{Protocol})$$

Direction is established by the initial TCP SYN handshake or the first observed UDP packet. Statistical features are tracked per direction:
- **Forward Flow ($A \to B$)**: Initiator requests, packet sizes, transmission intervals.
- **Backward Flow ($B \to A$)**: Server responses, acknowledgments, payload bytes.
- **Derived Rates**:
  $$\text{Flow Bytes/s} = \frac{\sum \text{Bytes}_{fwd} + \sum \text{Bytes}_{bwd}}{\max(\Delta t, 10^{-4})}$$
  $$\text{Flow Packets/s} = \frac{N_{fwd} + N_{bwd}}{\max(\Delta t, 10^{-4})}$$

### 3.2. Data Partitioning & Leakage Prevention (`netsentry.data`)
A pervasive flaw in academic ML-NIDS literature is **data leakage**:
1. **Preprocessing Leakage**: Computing scaler means/variances or imputer medians across the entire dataset before splitting. In NetSentry AI, `StandardScaler` and `SimpleImputer` exist *exclusively inside scikit-learn Pipeline objects*, fitted only on training folds.
2. **Session / Temporal Leakage**: Splitting flows randomly when multiple flows originate from the same attack session. NetSentry AI provides `SplitStrategy.TEMPORAL` and `SplitStrategy.GROUP` to test temporal generalizability.
3. **Target Leakage**: Features that inadvertently reveal the ground truth (such as flow sequence IDs, connection timestamps, or source IP subnets specific to attack machines). NetSentry's `detect_target_leakage()` identifies and strips these columns automatically.

### 3.3. Multi-Model Pipeline Engine (`netsentry.models`)
NetSentry AI constructs modular pipelines tailored to the mathematical requirements of each model family:
- **Distance & Linear Models (Logistic Regression, Linear SVM, KNN, MLP)**: Require scaling because features like `Flow Duration` ($10^7 \ \mu\text{s}$) would otherwise dominate unit-scale features like `TCP Flags`.
- **Tree-Based Models (Decision Tree, Random Forest, Extra Trees, HistGradientBoosting, LightGBM, XGBoost)**: Invariant to monotonic scaling, but require median imputation for robust handling of missing values or division-by-zero infinities.
- **Isolation Forest**: Unsupervised tree ensemble that isolates anomalies by measuring path lengths in random partitions, requiring no attack labels during training.

### 3.4. Decision Threshold Calibration & Alert Fatigue Mitigation (`netsentry.training.threshold`)
In operational Security Operations Centers (SOCs), a default threshold of $0.50$ is rarely optimal:
- At 1 Gbps, 100,000 flows per minute with a $2\%$ False Positive Rate generates **2,000 false alarms per minute**, inducing catastrophic alert fatigue.
- NetSentry AI sweeps the decision boundary from $0.05$ to $0.95$ on validation folds, identifying optimal thresholds under strict FPR constraints (e.g., $\text{FPR} \le 1.0\%$) to minimize analyst fatigue while maximizing attack recall.

### 3.5. Local & Global Explainability Engine (`netsentry.explainability`)
- **Global Feature Importance**: Identifies which network flow metrics govern model decisions across the enterprise.
- **Local Flow Attribution**: For any individual flagged connection, computes $z$-score deviations against normal traffic baselines:
  $$z_i = \frac{x_i - \mu_{\text{benign}, i}}{\sigma_{\text{benign}, i}}$$
- **Plain-English Security Narratives**: Translates complex ML decision mathematics into actionable, student-friendly incident reports with concrete SOC firewall remediation recommendations.

---

## 4. Software Design & Coding Standards
- **Python Version**: 3.12+ 64-bit.
- **Package Layout**: Modular `src/netsentry/` layout with `pyproject.toml`.
- **Backward Compatibility**: Fully preserves legacy entry points (`python -m netsentry.train`, `python -m netsentry.predict`).
- **Typing & Documentation**: Full type annotations (`typing`), dataclasses, and DCN-grounded docstrings across all modules.
- **Testing**: 100% automated test coverage with `unittest` running in under 10 seconds.
