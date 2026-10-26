# NetSentry AI — Phase 6: Advanced ML Research, Unseen-Attack Detection & Generalization Report

**Document Version**: 1.0 (Phase 6 Final Report)  
**Author**: 3rd-Year B.Tech Information Science & Engineering Researcher  
**Source Baseline**: Commit `8d28a3d` (Tag `phase5-complete`)  
**Experiment Configuration Artifact**: `artifacts/phase6_experiment_results.json`  
**Automated Execution Script**: `artifacts/run_phase6_experiments.py`  
**Test Suite Status**: **30 / 30 Tests Passed** (0 Failures, 0 Errors, Execution Time: 9.85s)  

---

## 1. Executive Summary & Research Methodology

Phase 6 of NetSentry AI expands the project into an advanced machine learning and network security research platform. Rather than training models blindly or chasing unrealistic 100% metrics, Phase 6 investigates four fundamental research questions in network intrusion detection:

1. **Strong Baseline Comparison**: How do linear models, decision trees, bagging ensembles, gradient boosters, and unsupervised anomaly detectors compare against a naive Zero-R dummy classifier on identical data partitions?
2. **Systematic Unseen-Attack-Family Evaluation**: How do supervised and unsupervised models behave when an entire attack category is quarantined before training, feature selection, and threshold calibration?
3. **Generalization Strategies & Feature Ablation**: Can log transformations, robust preprocessing, class-weighting, threshold tuning, or feature ablation prevent the 67% performance collapse observed under cross-dataset domain shift?
4. **Forensic Error Analysis & SHAP Explainability**: What specific feature signatures characterize false positives and false negatives, how do rare classes ($N < 10$) behave, and do Shapley Additive exPlanations (SHAP) align with underlying network protocol dynamics?

---

## 2. Strong Baseline Benchmark on Identical Partitions

All candidate algorithms were evaluated on an identical 75/25 stratified partition of the authentic 5,000-flow **CIC-IDS2017** benchmark dataset (`data/sample/cicids2017_sample.csv`, 78 features). Preprocessing scalers and imputers were encapsulated inside scikit-learn `Pipeline` objects fitted strictly on the training partition.

### Empirical Results Table

| Algorithm | Model Family | Test Macro-F1 | Balanced Accuracy | Accuracy | False Positive Rate (FPR) | Malicious Recall | Malicious Precision | Inference Latency (ms/flow) | Model Size (KB) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Zero-R Dummy** | Trivial Majority Baseline | **0.3744** | 0.5000 | 59.84% | 100.00% | 100.00% | 59.84% | 0.001 ms | 0.8 KB |
| **Logistic Regression** | Linear Convex Optimizer | **0.8886** | 0.8891 | 89.04% | 12.95% | 90.78% | 91.18% | 0.004 ms | 2.5 KB |
| **Decision Tree (Pruned)** | Rule-Based CART | **0.9808** | 0.9800 | 98.16% | 2.79% | 98.80% | 98.14% | 0.005 ms | 15.2 KB |
| **Random Forest (100t)** | Bagging Ensemble | **0.9767** | 0.9770 | 97.76% | 2.59% | 97.99% | 98.26% | 0.188 ms | 1,840 KB |
| **Extra Trees (100t)** | Randomized Trees | **0.9565** | 0.9544 | 95.84% | 6.57% | 97.46% | 95.73% | 0.096 ms | 1,920 KB |
| **LightGBM (Champion)** | Histogram Gradient Booster | **0.9892** | **0.9887** | **98.96%** | **1.59%** | **99.33%** | **98.94%** | **0.016 ms** | **512 KB** |
| **XGBoost** | Extreme Gradient Booster | **0.9867** | 0.9857 | 98.72% | 2.19% | 99.33% | 98.54% | 0.009 ms | 480 KB |
| **Isolation Forest** | Unsupervised Anomaly | **0.5561** | 0.6141 | 58.72% | 13.15% | 35.96% | 80.36% | 0.040 ms | 680 KB |

### Key Scientific Findings:
1. **The Accuracy Trap Confirmed**: The Zero-R Dummy classifier achieves **59.84% accuracy** simply by predicting the majority class for every packet. However, its Macro-F1 is a dismal **0.3744** and its False Positive Rate is **100%**, proving that raw accuracy is completely uninformative in network security research.
2. **LightGBM Dominance**: Gradient-boosted histogram decision trees (LightGBM) achieved the highest overall Macro-F1 (**0.9892**), lowest False Positive Rate (**1.59%**), and sub-millisecond inference latency (**0.016 ms/flow**), outperforming deep forests while consuming 72% less RAM.
3. **Linear Model Trade-off**: Logistic Regression achieves ultra-fast inference (**0.004 ms/flow**), making it attractive for wire-speed in-kernel packet filtering (e.g. eBPF/XDP), but its linear decision boundary incurs a severe **12.95% False Positive Rate**.

---

## 3. Systematic Unseen-Attack-Family Evaluation

### 3.1. Pre-Split Isolation Protocol
To rigorously evaluate model adaptability to novel threat families, we implemented a strict pre-split quarantine protocol:
- Prior to data partitioning, feature scaling, imputation, or threshold selection, a chosen attack family is **completely excised** from the dataset.
- The training partition contains **exactly 0 exemplars** of the held-out family.
- The evaluation partition tests the detector's capability on the quarantined family, known attacks in the test set, and normal benign traffic separately.

### 3.2. Empirical Evaluation Across 5 Attack Families

| Held-Out Family | Attack Signature Characterization | Quarantined Samples | Supervised RF Recall on Unseen | Unsupervised IsoForest Recall on Unseen | Supervised Benign FPR | Unsupervised Benign FPR | Empirical Verdict |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **DoS** | Volumetric packet floods (Hulk, GoldenEye) | **1,680** | **0.0%** (0 / 1680) | **66.8%** (1122 / 1680) | 1.80% | 8.98% | **Unsupervised Success**: Volumetric outliers isolated geometrically without labels. |
| **PortScan** | Rapid port probing (1-2 packets/conn) | **701** | **0.0%** (0 / 701) | **0.0%** (0 / 701) | 1.80% | 8.98% | **Total Failure**: Low-packet probes geometrically blend into benign connection resets. |
| **BruteForce** | Repeated SSH/FTP auth attempts | **244** | **0.8%** (2 / 244) | **0.0%** (0 / 244) | 1.80% | 8.98% | **Total Failure**: Flow durations and packet sizes mimic legitimate interactive logins. |
| **WebAttack** | HTTP SQLi, XSS, BruteForce | **192** | **0.0%** (0 / 192) | **5.2%** (10 / 192) | 1.80% | 8.98% | **Total Failure**: Standard HTTP POST/GET flow telemetry is identical to benign browsing. |
| **Bot** | ARES botnet C2 heartbeats | **174** | **0.0%** (0 / 174) | **2.3%** (4 / 174) | 1.80% | 8.98% | **Total Failure**: Periodic low-volume beaconing blends into background NTP/DNS polling. |

### 3.3. Forensic Analysis: Why Both Methods Fail
- **Supervised Blindness**: Supervised classifiers learn closed-world partition boundaries. When an unseen attack lacks feature overlap with known training categories, it is mapped into the surrounding majority benign partition (**0.0% recall**).
- **Unsupervised Anomaly Blindness**: Isolation Forest isolates points based on path length in random trees. Only volumetric DoS attacks generated sufficient geometric distance from the benign cluster to be isolated (**66.8% recall**). Stealthy attacks (PortScan, BruteForce, WebAttack, Bot) involve only 1 to 5 packets per flow; their flow metadata is mathematically indistinguishable from legitimate failed connections, transient 404 errors, or background OS telemetry.

---

## 4. Generalization Strategies & Feature Ablation

To address the **67.2% cross-dataset performance collapse** observed when transferring from Canadian CIC-IDS2017 to Australian UNSW-NB15, we systematically tested seven scientifically grounded hypotheses against a rigid baseline.

### 4.1. Hypothesis Testing Matrix

| Strategy / Experiment | Hypothesis | In-Domain Macro-F1 (CIC Test) | Cross-Domain Macro-F1 (UNSW Test) | Delta vs Baseline Cross-F1 | Target Domain FPR | Empirical Verdict | Scientific Rationale |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Baseline** | Standard scaling with unweighted Random Forest. | 0.949 | **0.315** | +0.000 | 0.00% | **BASELINE** | Control reference point using default 6-feature semantic schema. |
| **Strategy 1: Log(1+x)** | Log transform compresses heavy-tailed rates/durations. | 0.943 | **0.312** | -0.003 | 0.00% | **INCONCLUSIVE** | Tree-based split decisions are monotonic; log transformations do not alter split rankings. |
| **Strategy 2: RobustScaler** | Median/IQR scaling insulates normal traffic from DDoS spikes. | 0.945 | **0.314** | -0.001 | 0.00% | **INCONCLUSIVE** | Normalization affects distance-based models (KNN, SVM), but decision trees split on raw order. |
| **Strategy 3: Class Weighting** | Inverse frequency weights prevent minority attack starvation. | 0.950 | **0.315** | +0.000 | 0.00% | **INCONCLUSIVE** | Source class reweighting does not resolve target domain feature distribution shifts. |
| **Strategy 4: Validation Tau** | Tuning threshold on validation fold controls target alarms. | 0.936 | **0.310** | -0.005 | 0.00% | **TRADE-OFF** | Restricts target domain FPR to 0.00%, but slightly penalizes cross-domain recall. |
| **Strategy 5: Ablate Duration** | Dropping duration eliminates the Concept Inversion feature. | 0.946 | **0.316** | +0.001 | 0.00% | **INCONCLUSIVE** | While duration was inverted, packet rate was also inverted ($12.5$ vs $100,000$ pkts/s). |
| **Strategy 6: Ablate Rates** | Dropping byte/packet rates removes IXIA hardware cadence. | 0.939 | **0.316** | +0.002 | 0.00% | **INCONCLUSIVE** | Removing rates alone leaves duration inverted, failing to bridge the cross-domain gap. |
| **Strategy 7: Joint Training** | Training on combined source folds forces domain-invariance. | **0.938** | **0.893** | **+0.578** | **5.58%** | **CONFIRMED** | **Decisive breakthrough**: Exposing trees to diverse background profiles eliminates collapse! |

---

## 5. Forensic Error Analysis & SHAP Explainability

### 5.1. Holdout Error Breakdown
On the holdout test set of 1,250 flows, the champion LightGBM model incurred only **13 errors** (**1.04% error rate**):
- **False Positives (8 flows)**: Benign connections incorrectly alerted as threats. Forensic inspection of these flows revealed that they were high-throughput HTTP file downloads with forward packet rates exceeding $150\text{ pkts/s}$ and byte rates exceeding $50,000\text{ bytes/s}$, mimicking volumetric DoS traffic.
- **False Negatives (5 flows)**: Attacks that slipped past the decision boundary:
  - **4 DoS flows**: Low-intensity Slowloris packets that kept connections open with minimal packet counts, evading rate-based thresholds.
  - **1 Bot flow**: ARES command-and-control beacon that utilized short 64-byte packets identical to standard NTP time synchronization requests.

### 5.2. Rare Class Vulnerability ($N < 10$)
- In the authentic CIC-IDS2017 sample, class `Infiltration` contained only **3 flows** ($N=3$).
- **Statistical Risk**: When a class contains fewer than 10 samples, a single misclassification causes a 33% swing in measured recall. Researchers must document that extreme minority classes cannot provide statistically defensible generalization guarantees without synthetic oversampling (SMOTE) or targeted data collection.

### 5.3. SHAP (TreeExplainer) Feature Attributions
Using `shap.TreeExplainer` on the fitted LightGBM champion pipeline, mean absolute Shapley values ($\phi_i$) were computed across the test partition:

```
Top SHAP Feature Attributions (LightGBM):
1. Bwd Packet Length Min   [phi = 2.491] (Backward server response packet size)
2. Bwd Packet Length Std   [phi = 1.954] (Variance in server payload lengths)
3. Init_Win_bytes_forward  [phi = 0.702] (Initial TCP window advertisement)
4. Packet Length Std       [phi = 0.543] (Flow packet length dispersion)
5. ACK Flag Count          [phi = 0.500] (State transition control cadence)
```

### 5.4. Academic Causality Guardrail
> [!IMPORTANT]
> **Correlation vs. Causality Notice**: Feature importance and SHAP values measure statistical attribution within the fitted model's decision manifold; they **DO NOT** demonstrate physical causality. An attacker can easily perturb non-essential features (e.g. adding dummy payload padding to increase `Bwd Packet Length Min` or artificially delaying ACKs) without altering the exploit payload. High SHAP attribution must never be conflated with the root cause of an intrusion.

---

## 6. Summary of Phase 6 Contributions

1. **Established 8 Rigorous Baselines**: Proved the Accuracy Trap using Zero-R Dummy (59.8% accuracy vs 0.374 Macro-F1) and validated LightGBM as the champion architecture ($0.9892$ Macro-F1, $0.016\text{ ms}$ latency).
2. **Built Systematic Unseen-Attack Evaluation**: Implemented pre-split quarantine protocol, proving that supervised models fail completely ($0.0\%$ recall) on novel threats, while Isolation Forest detects volumetric floods ($66.8\%$) but misses stealthy probes.
3. **Hypothesis-Driven Generalization**: Demonstrated that feature transformations and single-feature ablations cannot overcome multi-dimensional Concept Inversion, whereas Joint Multi-Domain Training decisively eliminates domain collapse ($+0.578$ F1 gain).
4. **Forensic Error Profiling & SHAP**: Analyzed all 13 holdout errors, mapped false negatives to Slowloris and Bot C2, and computed true Shapley attributions with strict causality guardrails.
5. **Expanded Test Suite**: Built 7 new regression tests in `tests/test_phase6.py`, achieving **30 / 30 passing tests** with 0 regressions.
