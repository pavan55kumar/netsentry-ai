# NetSentry AI — Academic Research Paper Outline & Experimental Findings

**Title**: *Empirical Evaluation of Machine Learning Architectures for Flow-Based Network Intrusion Detection: Mitigating Alert Fatigue, Covariate Domain Shift, and Zero-Day Blindness*

**Author(s)**: Information Science Engineering Research Group, NetSentry AI Project  
**Target Venues**: IEEE Transactions on Network and Service Management (TNSM) / IEEE S&P / ACM CCS / Springer Journal of Network and Systems Management (JNSM)

---

## Abstract

As transport-layer encryption (TLS 1.3, QUIC) blinds traditional Deep Packet Inspection (DPI), Network Intrusion Detection Systems (NIDS) increasingly rely on statistical network connection flow metadata (NetFlow/IPFIX). However, academic literature is inundated with reports of near-perfect ($>99.5\%$) accuracy that collapse in operational deployments due to data leakage, class imbalance ("The Accuracy Trap"), and catastrophic domain shift. 

In this work, we present **NetSentry AI**, a leakage-free research framework and comparative benchmark across 11 machine learning architectures evaluated on authentic CIC-IDS2017 and UNSW-NB15 datasets. Our empirical results demonstrate:
1. **Model Hierarchy**: Gradient boosting architectures (LightGBM, XGBoost, HistGradientBoosting) consistently lead detection performance (Macro-$F_1 = 0.9892$, Accuracy $= 98.96\%$, $\text{FPR} = 1.59\%$, latency $= 0.013\text{ ms/flow}$), while single Decision Trees provide the fastest line-rate inference ($0.004\text{ ms/flow}$, $18.5\text{ KB}$ footprint).
2. **Alert Fatigue Mitigation**: Validation-based threshold calibration eliminates false positives ($\text{FPR} \to 0.00\%$) under strict operational constraints.
3. **Domain Shift Crisis**: Cross-dataset evaluation on standardized semantic flow features reveals a **$67.2\%$ Macro-$F_1$ collapse** (CIC-IDS2017 $\to$ UNSW-NB15), empirically proving severe covariate shift between network topologies.
4. **Zero-Day Blindness vs Unsupervised Discovery**: While supervised classifiers completely missed novel DoS attacks ($0.0\%$ recall) when held out during training, unsupervised Isolation Forest detected **$66.7\%$ of unseen DoS attacks**, demonstrating the essential complementary role of unsupervised anomaly detection.

---

## 1. Introduction & Motivation
- **The Modern Network Landscape**: Over 90% of web and enterprise traffic is encrypted with authenticated ciphers. Payload inspection is obsolete or violates privacy.
- **The Promise of Flow Telemetry**: Summarizing bidirectional packets into 5-tuples ($IP_{src}, IP_{dst}, Port_{src}, Port_{dst}, \text{Protocol}$) enables scalable, line-rate monitoring.
- **The Problem Statement**: Why do models published with 100% accuracy fail in production? Identifying the trio of failure modes:
  1. Data leakage (preprocessing and target leakage).
  2. The Accuracy Trap and Alert Fatigue.
  3. Inability to generalize across different capture environments (Domain Shift).

---

## 2. Related Work & The "100% Accuracy" Forensic Audit
- Review of benchmark datasets: KDD99, NSL-KDD, CIC-IDS2017, UNSW-NB15.
- Analysis of published papers claiming 99-100% accuracy.
- **NetSentry Forensic Audit**: Demonstration of how synthetic data generation in previous studies hardcoded linearly separable boundaries (e.g. DoS packets $>80$ vs geometric benign distributions), creating artificial perfection. Re-evaluation on genuine stratified UNB captures reveals realistic Macro-$F_1$ scores ($0.97 - 0.99$).

---

## 3. System Architecture & Methodology
- **Bidirectional Flow Aggregation**: Deriving flow duration, forward/backward packet counts, byte rates, packet rates, and TCP control flag counters (SYN, ACK, RST, FIN, PSH, URG).
- **Leakage-Free Pipeline Construction**: Independent fitting of `SimpleImputer` and `StandardScaler` strictly within cross-validation folds.
- **11 Model Implementations Across 6 Paradigms**:
  1. *Linear Models*: Logistic Regression, Calibrated Linear SVM (Platt scaling).
  2. *Decision Trees*: CART Decision Tree.
  3. *Bagging Ensembles*: Random Forest, Extra Trees.
  4. *Boosting Ensembles*: HistGradientBoosting, LightGBM, XGBoost.
  5. *Instance-Based*: K-Nearest Neighbors.
  6. *Deep Learning*: Multi-Layer Perceptron (Adam, ReLU).
  7. *Unsupervised Anomaly Detection*: Isolation Forest.

---

## 4. Empirical Evaluation on Authentic Datasets

### 4.1. Binary Classification Benchmark
- Complete metrics table on CIC-IDS2017 and UNSW-NB15: Macro-F1, Accuracy, Precision, Recall, FPR, FNR, Latency, Model Size.
- **Finding**: LightGBM achieves the best trade-off with $F_1 = 0.9892$, $\text{FPR} = 1.59\%$, and $0.013\text{ ms}$ latency.

### 4.2. Multi-Class Intrusion Benchmark
- Evaluation across 6 CIC-IDS2017 classes and 8 UNSW-NB15 classes.
- Analysis of minority attack categories: High recall on DoS ($>98\%$) and PortScan ($>99\%$), but pronounced challenge on minority categories (WebAttack $F_1 = 0.74 - 0.92$, Analysis $F_1 < 0.50$).

### 4.3. Alert Fatigue & Decision Threshold Calibration
- Mathematical derivation of the Base-Rate Fallacy in SOC environments.
- Validation threshold sweep curves: Demonstrating that shifting threshold from $0.50 \to 0.23$ on validation data reduces FPR to $0.0\%$ while preserving $100\%$ attack recall on validated DoS traffic.

---

## 5. Research Experiments

### 5.1. Experiment A: Cross-Dataset Domain Shift
- **Hypothesis**: Models trained on one capture environment memorize local feature scales and fail when transferred.
- **Harmonized 6-Feature Schema**: $\mathcal{F} = \{\text{duration}, \text{fwd\_pkts}, \text{bwd\_pkts}, \text{byte\_rate}, \text{pkt\_rate}, \text{avg\_pkt\_size}\}$.
- **Results**:
  - CIC $\to$ UNSW: In-domain $F_1 = 0.9442 \to$ Cross-domain $F_1 = 0.3101$ (**$67.2\%$ drop**).
  - UNSW $\to$ CIC: In-domain $F_1 = 0.8994 \to$ Cross-domain $F_1 = 0.4086$ (**$54.6\%$ drop**).
- **Discussion**: Explaining how differences in MTU, background B-Profile user habits, and IXIA hardware generators break fragile decision boundaries.

### 5.2. Experiment B: Unseen Zero-Day Attack Discovery
- **Setup**: Hold out entire attack families (`PortScan`, `DoS`) during supervised training.
- **Results**:
  - Supervised Random Forest: **$0.0\%$ recall** on unseen DoS and PortScan (complete blind spot).
  - Unsupervised Isolation Forest: **$66.7\%$ recall** on unseen DoS without any prior labels (at the expense of a $9.0\%$ benign false alarm rate).
- **Theoretical Insight**: Statistical anomaly detection flags geometric outliers, providing a vital safety net against novel zero-day attacks when combined with supervised filters.

### 5.3. Experiment C: Network Traffic Covariate Drift
- **Setup**: Systematically perturbing test features to simulate operational network evolution over months.
- **Results**:
  - Volumetric Rate Spike ($0.0 \to 2.0\times$): Macro-$F_1$ degraded from $0.9850 \to 0.6387$ (**$35.2\%$ drop**), and FPR escalated from $2.4\% \to 10.8\%$.
  - TCP Flag Mutation: Macro-$F_1$ degraded to $0.8766$ (**$11.0\%$ drop**).
  - Feature Jitter Noise: Macro-$F_1$ degraded to $0.5346$ (**$45.7\%$ drop**).

---

## 6. Real-World Limitations & Threats to Validity
- Software packet processing bottleneck in user-space Python ($<100,000\text{ pkts/sec}$).
- Inherent blindness of Layer 3/4 flow metadata to single-packet payload exploits (Log4Shell, SQLi).
- Detective nature of flow analysis due to 15–30 second flow collection windows.

---

## 7. Conclusion & Research Roadmap
- Summary of core findings: Ensembles of gradient-boosted trees provide optimal flow classification, but operational survivability demands active threshold tuning and domain adaptation.
- Future work: Integration of eBPF/XDP kernel bypass and self-supervised contrastive learning for zero-shot domain transfer.
