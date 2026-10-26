# NetSentry AI — Engineering Portfolio Case Study

**Project Name:** NetSentry AI — Machine Learning Network Intrusion Detection & Research Platform  
**Developer:** 3rd-Year B.Tech Student, Information Science & Engineering, NMAM Institute of Technology, Nitte  
**Repository Type:** Academic Research & Systems Engineering Prototype  
**Technologies:** Python 3.12, scikit-learn, LightGBM, XGBoost, Scapy, pandas, NumPy, Streamlit, SHAP  

---

## 1. Overview & Problem Statement

Modern enterprise networks transport tens of gigabits per second, with over 85% of traffic encrypted under TLS 1.3 or HTTPS. In this landscape, traditional Deep Packet Inspection (DPI)—which searches unencrypted packet payloads for signature strings—fails completely. Meanwhile, academic machine learning literature regularly claims $>99\%$ detection accuracy on benchmark datasets like CIC-IDS2017. 

However, when applied to operational security environments, these models suffer from three systemic failures:
1. **The Base-Rate Fallacy (Alert Fatigue):** On real networks, malicious traffic accounts for $<0.1\%$ of total volume. Even a model with 99% accuracy and a 1.5% False Positive Rate generates **over 94% false alarms**, overwhelming security analysts.
2. **Domain Shift & Concept Inversion:** Models trained on clean academic testbeds fail catastrophically when evaluated against traffic from different network topologies.
3. **Sensor Jitter Brittleness:** Tree-based models fit tightly around deterministic scripted attack intervals; real-world packet delay variation (PDV) and hardware clock drift cause severe classification failure.

**NetSentry AI** was designed to address these problems by combining Data Communication & Networking (DCN) flow reconstruction with production-grade ML engineering, rigorous data leakage prevention, physical stress-testing, and safe input handling.

---

## 2. System Architecture & Flow Pipeline

NetSentry AI processes raw network traffic and tabular telemetry through a modular five-stage pipeline:

```
┌─────────────────┐      ┌───────────────────────────┐      ┌─────────────────────────┐
│   Raw PCAP /    │ ───► │ 5-Tuple Flow Aggregation  │ ───► │  Zero-Leakage Pipeline  │
│   Flow CSVs     │      │   (120s Idle Timeout)     │      │ (Imputation + Scaling)  │
└─────────────────┘      └───────────────────────────┘      └─────────────────────────┘
                                                                         │
                                                                         ▼
┌─────────────────┐      ┌───────────────────────────┐      ┌─────────────────────────┐
│  Streamlit SOC  │ ◄─── │ Safe Failure Quarantine   │ ◄─── │  Multi-Paradigm Engine  │
│   Operations    │      │  (+Inf / -Inf -> Flag -1) │      │ (LightGBM, RF, IsoForest│
└─────────────────┘      └───────────────────────────┘      └─────────────────────────┘
```

1. **Flow Aggregation Engine (`src/netsentry/pcap/flow_extractor.py`):** Uses Scapy `PcapReader` to stream raw packet captures. Normalizes bidirectional conversations using the canonical 5-tuple `(src_ip, sport, dst_ip, dport, proto)` and a 120-second idle session timeout to compute duration, packet counts, byte rates, and TCP control flags.
2. **Leakage-Free Preprocessing (`src/netsentry/data/preprocessor.py`):** Automatically detects and drops ground-truth target indicators and direct session identifiers (`src_ip`, `dst_ip`, `flow_id`, `timestamp`). Prunes exact duplicate feature rows to prevent cross-partition leakage.
3. **Pipeline Construction (`src/netsentry/models/factory.py`):** Encapsulates `SimpleImputer`, `StandardScaler`/`RobustScaler`, and estimators inside `sklearn.pipeline.Pipeline`, guaranteeing all statistical transformations are fitted strictly on training folds.
4. **Inference & Quarantine Safety (`src/netsentry/predict.py`):** Enforces a strict safe failure policy: flows containing `+Inf`/`-Inf` from zero-duration rate calculations are assigned `prediction = -1` (`QUARANTINE_NON_FINITE`), preventing corrupted data from masquerading as benign traffic.
5. **Interactive Operations Center (`app/`):** An 8-view Streamlit dashboard providing real-time flow scoring, local $z$-score feature deviation explanations, plain-English SOC alert narratives, and privacy-preserving CSV telemetry exports with masked IP host octets (`192.168.1.***`).

---

## 3. Major Engineering Decisions & Trade-Offs

```
========================================================================================================
                                    ENGINEERING DECISION MATRIX
========================================================================================================
Design Choice               Selected Approach                Alternative Considered     Rationale
--------------------------------------------------------------------------------------------------------
Champion Architecture       LightGBM (Boosting Ensemble)     Deep Neural Net (MLP/LSTM) 12x faster inference (0.016ms),
                                                                                        77% smaller size (344 KB).
Packet Ingestion            Scapy PcapReader (Python native) TShark / C++ Libpcap       100% self-contained Python;
                                                                                        zero OS binary dependencies.
Data Isolation              sklearn Pipeline encapsulation   Pre-split global scaling   Prevents test set mean/variance
                                                                                        leakage into training fold.
Threshold Selection         Validation fold tuning           Default 0.50 threshold     Enforces strict FPR <= 1.0%
                                                                                        to mitigate alert fatigue.
Corrupted Input Handling    Safe Quarantine (Flag -1)        df.dropna() or median fill Prevents unphysical rates from
                                                                                        silently passing as benign.
========================================================================================================
```

---

## 4. Key Research Findings & Benchmarks

All metrics below are backed by serialized experiment artifacts in `artifacts/`:

### A. Algorithm Comparison (CIC-IDS2017 Stratified Sample, 5,000 flows)
- **LightGBM Champion:** Macro-F1 = **0.9892**, Accuracy = **98.96%**, FPR = **1.59%**, Malicious Recall = **99.33%**, Latency = **0.0156 ms/flow**, Footprint = **344 KB**.
- **Random Forest (500 trees):** Macro-F1 = **0.9767**, Accuracy = **97.76%**, FPR = **2.59%**, Latency = **0.1881 ms/flow**, Footprint = **1,508 KB**.
- **Decision Tree (CART):** Macro-F1 = **0.9808**, Accuracy = **98.16%**, Latency = **0.0049 ms/flow**, Footprint = **15 KB** (optimal for low-power edge filtering).

### B. Cross-Dataset Generalization & Concept Inversion
- **The Finding:** Evaluating a CIC-IDS2017 model on UNSW-NB15 caused Macro-F1 to collapse from **0.9488 to 0.3148** (a 66.82% degradation).
- **The Cause:** Feature ablation proved this was caused by **concept inversion** in flow duration: DoS attacks in CIC-IDS2017 have high duration (volumetric floods), while exploits in UNSW-NB15 have sub-second duration (automated probes).
- **The Solution:** Joint multi-domain training exposed the model to mixed source partitions, recovering cross-domain holdout F1 to **0.8932** (+0.5784 delta).

### C. Physical Robustness Stress Testing
- **Clock Jitter Brittleness:** Adding $\pm 5\%$ Gaussian noise to continuous timing features dropped LightGBM F1 from **0.9892 to 0.6617**, flipping **33.12% of predictions** (405 attacks flipped to benign) because orthogonal tree splits tightly envelop scripted attack intervals.
- **Enterprise Jumbo Frames (MTU 9000):** Scaling packet lengths to 8,960 bytes dropped F1 to **0.6639** (33.28% flips), as attack signatures were masked by bulk transfer sizes.
- **100 Gbps Line-Rate Burst:** Rate scaling preserved **0.9850 F1** (0.56% flips) due to monotonic tree threshold saturation.

---

## 5. Security & Operational Reliability

1. **Denial-of-Service Defense:** Enforced a strict 50 MB upload limit on CSV telemetry and raw PCAP captures, coupled with Scapy streaming iterators (`max_packets = 10000`).
2. **Temporary File Lifecycle:** Custom PCAP files are created via `tempfile.NamedTemporaryFile` in system temp and guaranteed unlinked in `finally` blocks upon completion or error.
3. **Privacy Masking:** Implemented `redact_ip_address()` to mask IPv4 host octets (`192.168.1.***`) and IPv6 endpoints (`2001:db8:85a3:****`). Scrubbed credentials, bearer tokens, AWS keys (`AKIA...`), and local student user profile directories (`[USER_DIR]/`) from logs.
4. **Automated Quality Gate:** Maintained 100% test pass rate across a comprehensive 63-test suite covering splitting, model pipelines, PCAP parsing, robustness perturbations, and security redactions.

---

## 6. Screenshots & Visual Artifacts

> *Note for Portfolio Reviewers: Screenshots can be captured live by launching `streamlit run app/main.py`.*

```
┌────────────────────────────────────────────────────────────────────────┐
│ [Screenshot Placeholder: Overview Dashboard]                           │
│ Caption: Executive Operations Center displaying KPI metrics, engine    │
│ status, and comparative radar charts.                                  │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│ [Screenshot Placeholder: Traffic Analyzer & PCAP Ingestion]            │
│ Caption: Real-time telemetry scoring with 5-tuple inspection,          │
│ quarantine badges, and plain-English SOC analyst alert narratives.     │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│ [Screenshot Placeholder: Research Hub & Robustness Perturbations]      │
│ Caption: Empirical failure analysis showing F1 drop under 5% jitter    │
│ and cross-dataset concept inversion ablation curves.                   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Individual Engineering Contributions

As a third-year undergraduate Information Science and Engineering student at NMAM Institute of Technology, Nitte, my individual contributions to NetSentry AI include:
- Designed and authored the complete Python package (`src/netsentry/`) and Streamlit application (`app/`).
- Implemented the bidirectional 5-tuple flow aggregation engine and idle session timeout logic using Scapy.
- Constructed zero-leakage scikit-learn pipelines with out-of-fold preprocessing and validation-based threshold optimization.
- Designed and executed the cross-dataset transfer experiments that identified concept inversion in flow duration.
- Programmed the physical robustness perturbation suite (jitter, jumbo frames, bursts, pacing) and analyzed the tree hyperplane boundary failure modes.
- Implemented the safe failure quarantine policy and privacy-preserving IP/log redaction utilities.
- Wrote the complete 63-test automated test suite and reproducibility guides.

---

## 8. Honest Limitations & Future Work

1. **Encrypted Payload Blindness:** Operates exclusively on L3/L4 metadata. It cannot detect zero-day exploits inside encrypted TLS 1.3 payloads unless the attack alters flow timing or packet counts.
2. **Hardware Capture Limits:** Scapy is a pure Python packet iterator operating at ~10,000 pkts/s for offline triage. A production 100 Gbps deployment requires kernel bypass drivers like DPDK or eBPF/XDP.
3. **Tree Hyperplane Brittleness:** Preserved negative finding: standard decision trees are sensitive to physical network timing jitter. Future work will investigate noise-augmented training and logarithmic feature discretization to harden split boundaries.
