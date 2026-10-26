# NetSentry AI — Live Demonstration Checklist & Technical Interview Defense Guide

**Target Audience**: 3rd-Year B.Tech Information Science and Engineering (ISE) Students  
**Purpose**: Step-by-step execution runbook for college lab evaluations, technical job interviews, project vivas, and conference demonstrations.  
**Estimated Demo Duration**: 5 to 7 Minutes  

---

## 1. Quick Environment Setup

Before launching the demonstration, ensure you are in the project root directory with your virtual environment active.

### 1.1. Terminal Verification
Open Windows PowerShell (or terminal) in `outputs/netsentry-ai`:

```powershell
# 1. Activate the Python virtual environment
.\.venv\Scripts\Activate.ps1

# 2. Verify Python version (requires Python 3.10+)
python --version
# Expected: Python 3.12.x or 3.11.x

# 3. Verify key dependencies are installed
python -c "import sklearn, lightgbm, xgboost, scapy, streamlit; print('All core libraries verified!')"
```

---

## 2. Step 1: Execute the Automated Test Suite (30 Seconds)

Start every technical demonstration by proving code reliability and test coverage.

### 2.1. Run Command
```powershell
python -m unittest discover -s tests -v
```

### 2.2. What to Point Out to the Interviewer
- **All 23 tests pass cleanly in under 7 seconds**.
- Point out test categories:
  - `test_data.py`: Validates chronological splits, target leakage detection, and infinite value sanitization.
  - `test_models.py`: Validates non-leaking pipeline construction, latency benchmarks, and LightGBM/XGBoost integration.
  - `test_pcap.py`: Tests raw packet reading, 5-tuple aggregation, and directional flow metrics.
  - `test_research.py`: Validates cross-dataset evaluation, model drift simulation, and zero-day attack detection.
- *Explain the Scapy warning*: Mention that on Windows, if WinPcap/Npcap is not installed, Scapy displays `WARNING: No libpcap provider available!`. Explain that NetSentry AI gracefully falls back to Scapy's pure-Python packet reader without crashing.

---

## 3. Step 2: Training and Evaluation Pipeline (1 Minute)

Demonstrate the command-line training pipeline, model persistence, and threshold calibration.

### 3.1. Train a High-Performance Champion Model
```powershell
# Train champion model using authentic CIC-IDS2017 subset
python -m netsentry.train --data data/real/cicids2017_sample.csv --output artifacts/best_model.joblib
```

### 3.2. What Happens Under the Hood
1. **Target Leakage Check**: Scans for columns encoding identifiers or class names.
2. **Stratified Split**: Partitions 75% for training, 25% holdout test set (untouched during hyperparameter selection).
3. **Pipeline Construction**: Fits `SimpleImputer(strategy='median')` and `StandardScaler()` *strictly on training folds*.
4. **Algorithm Training**: Trains the champion LightGBM classifier with histogram binning.
5. **Threshold Tuning**: Sweeps decision thresholds ($\tau \in [0.05, 0.95]$) on validation data to optimize F1 while constraining False Positive Rate.
6. **Artifact Storage**: Serializes pipeline into `artifacts/best_model.joblib`.

### 3.3. Evaluate the Model on Holdout Data
```powershell
python -m netsentry.evaluate --data data/real/cicids2017_sample.csv --model artifacts/best_model.joblib
```
- **Key Metrics to Highlight**:
  - Macro-F1: $\ge 0.98$
  - False Positive Rate: $\le 1.6\%$
  - Balanced Accuracy: $\ge 98.5\%$

---

## 4. Step 3: Launch the Interactive Web Application (30 Seconds)

Launch the premium Streamlit dashboard to demonstrate real-time telemetry, model explainability, and dataset exploration.

### 4.1. Launch Command
```powershell
streamlit run app/streamlit_app.py
```
- Open your browser at `http://localhost:8501`.

### 4.2. Recommended Navigation Path (3 Minutes)

#### A. Executive Overview (`app/views/overview.py`)
- Show the **Active Champion Model Badge** (`LightGBM Classifier`).
- Point out the **Security Operations Center (SOC) KPI Cards**:
  - Total Monitored Flows ($5,000$).
  - Mean Detection Macro-F1 ($98.92\%$).
  - Live False Positive Rate ($1.59\%$).
  - Sub-millisecond Inference Latency ($0.013\text{ ms/flow}$).

#### B. Dataset Explorer (`app/views/explorer.py`)
- Toggle between **UNB CIC-IDS2017** and **UNSW-NB15**.
- Show the verified **SHA-256 cryptographic checksums** (`data/provenance.json`).
- Explain the DCN flow feature distributions: `Flow Duration`, `Total Fwd Packets`, `Flow Bytes/s`.

#### C. Model Benchmark Lab (`app/views/model_lab.py`)
- Show the multi-paradigm comparison table spanning 11 algorithms:
  - Linear models (Logistic Regression).
  - Tree-based models (Decision Tree, Random Forest, Extra Trees).
  - Gradient Boosters (LightGBM, XGBoost, CatBoost).
  - Unsupervised Anomaly Detectors (Isolation Forest).
- Point out the **Zero-R Majority Dummy Classifier** baseline. Explain how it exposes the **"Accuracy Trap"** (a dummy model scores 54.6% accuracy but 0.0 Macro-F1 on minority attacks).

#### D. Decision Threshold & SOC Alert Tuning (`app/views/evaluation.py`)
- Show the interactive probability threshold slider.
- Explain: *"By raising or lowering the decision threshold $\tau$, a SOC manager can choose between catching 99.8% of attacks or strictly eliminating false alarms to prevent analyst burnout."*

---

## 5. Step 4: Live Traffic Analysis & Offline PCAP Ingestion (1 Minute)

Demonstrate real-time inference on raw network traffic captures.

### 5.1. Live PCAP Ingestion in the UI
1. Navigate to the **Traffic Analyzer** tab (`app/views/traffic_analyzer.py`).
2. Click **Upload File** and select `data/sample/test_traffic.pcap`.
3. Click **"Analyze Ingested Traffic"**.
4. Show the live parsed 5-tuple table:
   - Source IP, Destination IP, Source Port, Destination Port, Protocol (`TCP`).
5. Show the risk classifications and confidence scores.

### 5.2. Explainable AI (XAI) Narrative
1. Click on an alerted flow to expand the **Explainability** breakdown.
2. Show the **Local $z$-score Feature Deviations**:
   - E.g., `Flow Packets/s` is $+4.8\sigma$ above normal traffic baseline.
3. Show the **Automated SOC Action Recommendation**:
   - Plain-English advice: *"High-confidence DoS connection detected on destination port 80. Immediate action: Apply rate-limiting ACL on source IP."*

### 5.3. CLI Alternative for Terminal-Only Interviewers
```powershell
python -m netsentry.predict --input data/sample/synthetic_traffic.csv --model artifacts/best_model.joblib
```
- Outputs instant tabular risk scores (`NORMAL`, `SUSPICIOUS`, `MALICIOUS`) directly to the console.

---

## 6. Step 5: Demonstrate Cross-Dataset Evaluation & Model Failure (1 Minute)

This is the most impressive part of the interview. Showing where and why a model **fails** demonstrates deep scientific maturity far beyond a simple tutorial project.

### 6.1. Run the Cross-Dataset Experiment
```powershell
python artifacts/run_phase5_audit_experiments.py
```

### 6.2. The Failure to Explain (The 67% Drop)
- **Observation**: A champion model trained on Canadian CIC-IDS2017 drops from **0.9848 Macro-F1** down to **0.3229 Macro-F1** when tested on Australian UNSW-NB15. It misses 2,748 out of 2,753 attacks!

### 6.3. The 30-Second Technical Explanation (Concept Inversion)
> *"This failure is caused by **Concept Inversion**. In CIC-IDS2017, attacks were slow application-layer DoS (Slowloris) with a median duration of $0.62\text{ seconds}$ versus $0.03\text{ seconds}$ for normal traffic. In UNSW-NB15, attacks were microsecond exploit bursts from the IXIA PerfectStorm generator with a median duration of $0.00001\text{ seconds}$. The decision tree learned the rule: 'Short duration = Normal traffic.' When deployed on UNSW-NB15, this rule caused the model to classify 99.9% of attacks as benign."*

### 6.4. The Solution: Joint Multi-Domain Training
- Point to the joint training results in the terminal output:
  - Training on combined source folds from both domains forces the tree to find domain-invariant features.
  - Achieves **0.9425 Mean Macro-F1 on untouched CIC-IDS2017 test** and **0.9003 Mean Macro-F1 on untouched UNSW-NB15 test** across 5 repeated random seeds!

---

## 7. Ten Concise Interview Explanations (Cheat Sheet)

Memorize these 1-2 sentence answers for rapid-fire interview questions:

### 1. What is a packet vs a network flow?
> "A **packet** is a single discrete Layer 3/4 datagram with a header and payload. A **network flow** is an aggregated, bidirectional summary of all packets exchanged between two endpoints during a communication session, characterized by statistical properties like duration, packet counts, and byte rates."

### 2. What is the 5-tuple and what are TCP flags?
> "The **5-tuple** uniquely identifies a connection: Source IP, Destination IP, Source Port, Destination Port, and Transport Protocol. **TCP flags** are 1-bit header fields (SYN, ACK, FIN, RST, PSH, URG) that govern connection state; for example, a flood of SYN flags without subsequent ACKs indicates a SYN-Flood DoS attack."

### 3. How are features and labels constructed in NetSentry AI?
> "Features are numerical aggregations extracted from packet streams—such as flow duration, forward/backward packet counts, packet length variance, and flag rates. Labels are ground-truth classifications assigned from security testbed logs, mapped into binary states (0=Benign, 1=Malicious) or multi-class threat categories (DoS, PortScan, BruteForce, Bot, WebAttack)."

### 4. How do training, validation, and testing partitions differ?
> "**Training data** is used by the algorithm to learn mathematical weights and decision splits. **Validation data** (or inner cross-validation folds) is used exclusively to tune hyperparameters and calibrate decision thresholds. The **Test partition** is a strictly isolated holdout evaluated once at the very end to measure true out-of-sample generalization without leakage."

### 5. Why is Macro-F1 more informative than accuracy for NIDS?
> "Accuracy is vulnerable to the **Accuracy Trap**: in imbalanced network traffic (e.g. 99% benign, 1% attack), a naive model predicting 'Benign' for every packet achieves 99% accuracy while missing all attacks. **Macro-F1** calculates the unweighted arithmetic mean of F1 scores across all classes, giving equal weight to rare cyber threats regardless of their volume."

### 6. How does False Positive Rate (FPR) differ from the proportion of alerts that are false?
> "**False Positive Rate (FPR)** is $FP / (FP + TN)$—the probability that legitimate traffic triggers an alarm. The **proportion of alerts that are false** is $1 - \text{Precision} = FP / (TP + FP)$. Due to the **Base-Rate Fallacy**, because attacks are extremely rare ($<0.01\%$), even a tiny 1.59% FPR causes over **99.4% of all generated alerts to be false alarms** in production."

### 7. Why do machine learning models fail under domain shift?
> "Models fail because of **Covariate Shift** (input feature distributions change) and **Concept Drift / Inversion** (the statistical relationship between features and the target label reverses). A model trained in one network topology memorizes capture-specific artifacts (like packet timing or background protocols) that do not translate to a different environment."

### 8. Why do supervised classification and unsupervised anomaly detection complement each other?
> "Supervised models (like LightGBM) excel at identifying **known attack families** with high accuracy ($>98\%$), but have 0% recall on novel, unseen threats. Unsupervised models (like Isolation Forest) require no labels and can detect **zero-day volumetric anomalies** based on geometric isolation, but suffer from higher false positive rates and cannot detect low-volume stealth attacks."

### 9. How does PCAP ingestion work and what are its physical limitations?
> "PCAP ingestion reads raw Ethernet frames via Scapy, hashes packets into 5-tuples, and aggregates directional timing and byte statistics into a tabular feature vector. Its primary limitations are **throughput** (user-space Python cannot handle 10 Gbps line rates without kernel-bypass like DPDK/eBPF) and **export latency** (flows are exported only after connection termination or timeout, making it detective rather than inline preventative)."

### 10. What is the single most important limitation of this project?
> "NetSentry AI operates on **flow metadata rather than application payloads**. While this preserves user privacy and functions over TLS 1.3 encrypted traffic, it is fundamentally blind to application-layer exploits—such as SQL injection, Log4Shell, or malicious file downloads—which produce flow statistics identical to legitimate HTTP traffic."

---

## 8. Common Troubleshooting Steps

If something unexpected happens during a live demo, stay calm and use these proven solutions:

| Issue | Root Cause | Instant Fix |
| :--- | :--- | :--- |
| **`Port 8501 is already in use`** | A previous Streamlit instance was not terminated. | Run `streamlit run app/streamlit_app.py --server.port 8502` or kill the task using `Get-Process python \| Stop-Process` in PowerShell. |
| **`WARNING: No libpcap provider available!`** | Npcap/WinPcap is not installed in the Windows OS. | Explain to the interviewer that Scapy uses pure-Python fallback. It does not affect functionality. |
| **`SchemaValidationError: Expected 77 features, got 8`** | An 8-feature PCAP was passed to a model trained on 77-feature CIC-IDS2017 data. | In the UI or CLI, select the model trained on the standard feature set (`artifacts/best_model.joblib`) or retrain using `--demo`. |
| **`ModuleNotFoundError: No module named 'netsentry'`** | Running Python from a subdirectory without installing editable package. | Run from the workspace root or ensure `PYTHONPATH=.` is set: `$env:PYTHONPATH="."`. |
| **Missing Model File (`artifacts/best_model.joblib`)** | Model was not trained yet on the current machine. | Run `python -m netsentry.train --demo` (takes 2 seconds) to immediately generate the artifact. |
