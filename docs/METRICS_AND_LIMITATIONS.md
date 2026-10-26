# NetSentry AI — Comprehensive Metrics Inventory & Scientific Limitations

## 1. Metrics Inventory & Provenance Categorization

In scientific research, claims must be explicitly tied to verifiable empirical evidence. The table below classifies all major project metrics into three strict audit categories:
1. **Independently Reproduced in Phase 9:** Rerun, recalculated, or programmatically validated during the Phase 9 audit.
2. **Existing Recorded Results Not Rerun in Phase 9:** Historical metrics preserved from earlier phases, with verified serialized artifacts on disk.
3. **Unverified Claims:** Statements that cannot be verified without multi-gigabyte external datasets or closed-source enterprise hardware.

```
========================================================================================================================
                                           RESEARCH METRICS AUDIT MATRIX
========================================================================================================================
Metric Identifier            Reported Value       Provenance Artifact              Status Category
------------------------------------------------------------------------------------------------------------------------
LightGBM Holdout Macro-F1    0.9892               artifacts/phase6_experiment...   1. Independently Reproduced (Phase 9)
LightGBM Holdout FPR         0.0159 (1.59%)       artifacts/phase6_experiment...   1. Independently Reproduced (Phase 9)
Random Forest Macro-F1       0.9767               artifacts/phase6_experiment...   1. Independently Reproduced (Phase 9)
Random Forest Holdout FPR    0.0259 (2.59%)       artifacts/phase6_experiment...   1. Independently Reproduced (Phase 9)
Decision Tree Inference Lat. 0.0049 ms/flow       artifacts/phase6_experiment...   1. Independently Reproduced (Phase 9)
LightGBM Inference Latency   0.0156 ms/flow       artifacts/phase6_experiment...   1. Independently Reproduced (Phase 9)
Cross-Domain Baseline F1     0.3148 (66.8% drop)  artifacts/phase6_experiment...   1. Independently Reproduced (Phase 9)
Joint Multi-Domain F1        0.8932 (+0.578 delta) artifacts/phase6_experiment...  1. Independently Reproduced (Phase 9)
Unseen DoS Supervised Recall 0.0% (Blind spot)    artifacts/phase6_experiment...   1. Independently Reproduced (Phase 9)
Unseen DoS IsoForest Recall  66.79% (2/3 detected) artifacts/phase6_experiment...  1. Independently Reproduced (Phase 9)
Unseen DoS IsoForest FPR     0.0758 (7.58% false) artifacts/phase6_experiment...   1. Independently Reproduced (Phase 9)
5% Jitter LightGBM F1        0.6617 (33.1% flips) artifacts/phase7_robustness...   1. Independently Reproduced (Phase 9)
5% Jitter Flips (Mal->Ben)   405 attack flows     artifacts/phase7_robustness...   1. Independently Reproduced (Phase 9)
Jumbo Frames (MTU 9000) F1   0.6639 (33.3% flips) artifacts/phase7_robustness...   1. Independently Reproduced (Phase 9)
100 Gbps Burst Line-Rate F1  0.9850 (0.56% flips) artifacts/phase7_robustness...   1. Independently Reproduced (Phase 9)
Adversarial Pacing Evasion   4 (LGBM) / 27 (RF)   artifacts/phase7_robustness...   1. Independently Reproduced (Phase 9)
Non-Finite Input Quarantine  100% (-1 flag)       artifacts/phase7_robustness...   1. Independently Reproduced (Phase 9)
5-Seed Stability (CIC-IDS)   0.9822 ± 0.0054      artifacts/phase5_audit_res...    2. Recorded Result (Phase 5)
5-Seed Stability (UNSW-NB15) 0.9919 ± 0.0023      artifacts/phase5_audit_res...    2. Recorded Result (Phase 5)
Alert Fatigue (0.1% Prev.)   94.09% False Alarms  artifacts/phase5_audit_res...    2. Recorded Result (Phase 5)
Alert Fatigue (0.01% Prev.)  99.38% False Alarms  artifacts/phase5_audit_res...    2. Recorded Result (Phase 5)
Full 2.8M-Row CIC Holdout F1 0.9905               PHASE3_VALIDATION_REPORT.md      3. Unverified (Requires full 50GB capture)
Full 2.5M-Row UNSW Holdout   0.9880               PHASE3_VALIDATION_REPORT.md      3. Unverified (Requires full 100GB PCAPs)
100 Gbps Hardware Throughput Line-rate ASIC drop  technical_architecture.md        3. Unverified (Requires physical FPGA/NIC)
========================================================================================================================
```

---

## 2. Comprehensive Scientific and Operational Limitations

A defensible research project must state its boundaries candidly. Below is an exhaustive breakdown of the technical and theoretical limitations of NetSentry AI.

### 2.1 Domain Shift and Concept Inversion
- **The Phenomenon:** When a model trained on CIC-IDS2017 is tested on UNSW-NB15, Macro-F1 collapses by **66.82%** (from 0.9488 to 0.3148).
- **Underlying Cause:** Academic intrusion datasets reflect the idiosyncratic background traffic and synthetic attack tools of their originating testbeds. In CIC-IDS2017, DoS floods are long-lived volumetric sessions. In UNSW-NB15, automated exploits are microsecond single-packet probes.
- **Limitation:** Models trained on single-organization network telemetry cannot generalize to new network topologies without domain adaptation or joint multi-domain training.

---

### 2.2 The Base-Rate Fallacy & Alert Fatigue in Security Operations Centers (SOCs)
- **The Phenomenon:** Despite achieving an apparently exceptional holdout accuracy of 98.96% and False Positive Rate of 1.59%, NetSentry AI will overwhelm human analysts in production.
- **Mathematical Reality:** On enterprise networks, malicious traffic accounts for $< 0.1\%$ of total flows. Applying Bayes' Theorem:
  - At 0.1% prevalence (1 malicious flow per 1,000 benign flows), **94.09% of all alerts presented to the SOC are false alarms**.
  - At 0.01% prevalence (1 in 10,000 flows), **99.38% of all alerts are false alarms**.
- **Limitation:** In a 10 Gbps environment processing 100,000 flows/second, a 1.59% FPR generates over **137 million false alarms every 24 hours**. Supervised classifiers cannot be deployed as raw alerting sensors without downstream correlation or aggressive threshold tuning.

---

### 2.3 Vulnerability to Continuous Measurement Jitter (NIC Clock Drift)
- **The Phenomenon:** Adding $\pm 5\%$ zero-mean Gaussian noise to continuous timing features causes LightGBM Macro-F1 to collapse from **0.9892 to 0.6617**, flipping **33.12% of all test predictions** (and flipping 405 malicious attacks to benign).
- **Underlying Cause:** Decision tree ensembles construct orthogonal, axis-aligned step functions in continuous feature space. When automated attack tools produce deterministic packet intervals, the tree fits tightly around these clusters. Normal packet delay variation (PDV), switch queueing, or NIC interrupt coalescing naturally shifts packet timings past the decision boundary.
- **Limitation:** Clean academic benchmark accuracy does not reflect real-world stability under physical measurement noise. Production models require noise-augmented training and logarithmic feature binning.

---

### 2.4 Adversarial Evasion via Rate Pacing and Payload Encryption
- **The Phenomenon:** In Phase 7, dilating flow durations 10x allowed 4 attacks to evade LightGBM and 27 attacks to evade Random Forest without altering exploit bytes.
- **Payload Blindness:** NetSentry AI operates exclusively on L3/L4 statistical flow headers (packet counts, durations, byte rates). It performs **zero Deep Packet Inspection (DPI)** of packet payloads.
- **Limitation:**
  1. Attackers utilizing Low-and-Slow pacing (e.g. Slowloris or slow SSH brute forcing) easily blend into benign volumetric distributions.
  2. Attackers transmitting modern exploits over encrypted TLS 1.3, HTTPS, or SSH are completely invisible to L4 metadata classifiers unless the payload causes abnormal flow-level timing anomalies.

---

### 2.5 The Unseen-Attack Dilemma: Supervised Blindness vs Unsupervised False Alarms
- **Supervised Classifiers:** When an attack family (e.g. DoS, PortScan, BruteForce) is withheld from training data, supervised models exhibit **0.0% recall** on novel attack geometries.
- **Unsupervised Anomaly Detectors (Isolation Forest):** Successfully isolated **66.79% of unseen DoS floods** without prior labels because volumetric bursts create geometric outliers.
- **The Trade-Off:**
  1. Isolation Forest completely failed (**0.0% recall**) on stealthy probes (`PortScan`, `BruteForce`) because low-packet scans geometrically overlap with benign web browsing.
  2. Isolation Forest incurred an unacceptable **7.58% to 11.39% False Positive Rate** on normal traffic.
- **Limitation:** There is no "silver bullet" zero-day detector. Volumetric anomalies are detectable without labels, but low-rate targeted intrusions require protocol state tracking and signature correlation.

---

### 2.6 Engineering & Hardware Ingestion Boundaries
- **Packet Ingestion Engine:** NetSentry AI uses Scapy `PcapReader` in Python. While robust for offline PCAP ingestion (~10,000 pkts/s), it cannot process wire-speed 100 Gbps traffic (which requires hardware TCAMs, eBPF, or DPDK).
- **Schema Mismatch:** Offline PCAP ingestion computes 8 canonical flow features. Academic research benchmarks on CIC-IDS2017 require 77 features. The PCAP viewer is a demonstration tool, not an end-to-end 77-feature DPI engine.
- **Model Serialization:** Serialized pipelines use Python `joblib`. Untrusted model loading is unsafe; NetSentry AI strictly limits model loading to local repository artifacts.

---

## 3. Recommendations for Future Research (Phase 10 & Beyond)

1. **Noise-Augmented Robust Training:** Inject continuous Gaussian noise ($\sigma = 0.05$) into training sets to prevent decision trees from forming overly brittle split boundaries.
2. **Multi-Domain Pretraining:** Standardize feature definitions across 3+ public corpora (CIC-IDS2017, UNSW-NB15, TON_IoT) to learn domain-invariant representations.
3. **Hybrid Detection Engine:** Cascade high-throughput supervised filters (LightGBM) with secondary unsupervised anomaly scorers (Isolation Forest) and Snort/Suricata signature rules.
4. **eBPF Kernel Collector:** Replace Python Scapy packet reading with an in-kernel eBPF bytecode collector to aggregate wire-speed flows directly in the Linux network stack.
