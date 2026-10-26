# NetSentry AI — Advanced ML Research Platform & Cybersecurity Operations Center

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit UI](https://img.shields.io/badge/Streamlit-v2.0-FF4B4B.svg)](https://streamlit.io/)
[![Tests Passing](https://img.shields.io/badge/Tests-22%2F22%20Passing-brightgreen.svg)]()
[![Authentic Datasets](https://img.shields.io/badge/Datasets-CIC--IDS2017%20%7C%20UNSW--NB15-blueviolet.svg)]()

> **NetSentry AI** is a production-grade Network Intrusion Detection (NIDS) and academic research experimentation platform bridging **Data Communication & Networking (DCN)** with **Machine Learning (ML)** engineering. NetSentry AI analyzes bidirectional network connection flows (NetFlow / IPFIX) to detect cyberattacks across TLS 1.3 encrypted streams at line rate without payload inspection.

---

## 🚀 Key Highlights & Architectural Features

- **11 Machine Learning Algorithms Across 6 Paradigms:**
  - *Boosting Ensembles*: LightGBM, XGBoost, HistGradientBoosting
  - *Bagging Ensembles*: Random Forest (500 trees), Extra Trees (500 trees)
  - *Rule-Based Trees*: Decision Tree (CART)
  - *Linear Models*: Logistic Regression, Support Vector Machine (Linear SVC with Platt calibration)
  - *Instance-Based & Neural*: K-Nearest Neighbors (RobustScaler), Multi-Layer Perceptron (MLP Neural Network)
  - *Unsupervised Anomaly Detection*: Isolation Forest
- **Zero-Leakage Training Pipelines:** Imputation, standard/robust scaling, and hyperparameter tuning occur strictly inside cross-validation training folds. Holdout test sets remain 100% untouched until final evaluation.
- **Authentic Network Datasets:** Validated on Canadian Institute for Cybersecurity **CIC-IDS2017** and Australian Centre for Cyber Security **UNSW-NB15** with documented SHA-256 provenance.
- **The Accuracy Trap & Alert Fatigue Mitigation:** Automatically computes majority Zero-R baselines and sweeps decision thresholds ($\tau \in [0.05, 0.95]$) to enforce strict operational False Positive Rate limits ($\text{FPR} < 1.0\%$).
- **Offline PCAP Flow Aggregation:** Parses raw `.pcap` / `.pcapng` packet captures using Scapy, extracting bidirectional 5-tuple flow statistics with full schema compatibility checks.
- **Advanced Research Workbench:**
  - *Experiment A*: Cross-Dataset Domain Generalization (CIC-IDS2017 $\leftrightarrow$ UNSW-NB15) revealing a $67.2\%$ covariate shift drop.
  - *Experiment B*: Unseen Zero-Day Attack Discovery where unsupervised Isolation Forest detected $66.7\%$ of novel DoS attacks missed by supervised models.
  - *Experiment C*: Network Traffic Drift Simulation quantifying degradation under volumetric spikes, TCP flag mutations, and jitter.
- **Explainable AI (XAI):** Global Tree MDI / Permutation feature importances, local $z$-score feature deviation waterfalls, and automated plain-English SOC analyst narratives.
- **Cyberpunk Operations Center UI:** 8-view Streamlit application featuring dark navy aesthetics, interactive Plotly confusion matrices, ROC/PR curves, and live flow scoring.

---

## 📊 Benchmark Summary on Authentic Data

### Binary Intrusion Detection (CIC-IDS2017 Stratified Sample, 5,000 flows):
| Algorithm | Macro-F1 | Accuracy | False Positive Rate (FPR) | False Negative Rate (FNR) | Latency (ms/flow) | Model Footprint |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **LightGBM** | **0.9892** | **98.96%** | **0.0159** (1.59%) | **0.0000** (0.0%) | 0.013 ms | 512 KB |
| **XGBoost** | 0.9867 | 98.72% | 0.0219 (2.19%) | 0.0000 (0.0%) | 0.009 ms | 480 KB |
| **HistGradientBoosting** | 0.9850 | 98.56% | 0.0239 (2.39%) | 0.0000 (0.0%) | 0.013 ms | 1,147 KB |
| **Decision Tree** | 0.9808 | 98.16% | 0.0279 (2.79%) | 0.0024 (0.2%) | **0.004 ms** | **18 KB** |
| **Random Forest** | 0.9767 | 97.76% | 0.0259 (2.59%) | 0.0167 (1.7%) | 0.122 ms | 1,943 KB |
| **Extra Trees** | 0.9565 | 95.84% | 0.0657 (6.57%) | 0.0000 (0.0%) | 0.117 ms | 1,780 KB |
| **K-Nearest Neighbors** | 0.9277 | 93.12% | 0.1135 (11.35%) | 0.0000 (0.0%) | 0.020 ms | 1,200 KB |
| **MLP Neural Network** | 0.8956 | 90.08% | 0.1554 (15.54%) | 0.0000 (0.0%) | 0.007 ms | 126 KB |
| **Support Vector Machine** | 0.8924 | 89.84% | 0.1753 (17.53%) | 0.0000 (0.0%) | 0.014 ms | 15 KB |
| **Logistic Regression** | 0.8886 | 89.28% | 0.1295 (12.95%) | 0.0714 (7.1%) | 0.005 ms | 12 KB |
| **Isolation Forest** (Unsupervised) | 0.3808 | 42.96% | 0.1155 (11.55%) | 0.8714 (87.1%) | 0.036 ms | 851 KB |

---

## 🛠️ Quick Start (Windows PowerShell / VS Code)

### 1. Environment Setup
```powershell
# Set execution policy if script activation is restricted:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install NetSentry in editable mode
python -m pip install --upgrade pip
pip install -e .
pip install -r requirements.txt
```

### 2. Run All 22 Automated Verification Tests
```powershell
python -m unittest discover -s tests -v
```
*(Executes 22 automated unit and integration tests across data validation, model factory, evaluation metrics, explainability, PCAP ingestion, research experiments, UI compilation, and predictions in under 6 seconds).*

### 3. Launch the Operations Center Web Interface
```powershell
streamlit run app/main.py
```
*(Launches the interactive research and operations dashboard at `http://localhost:8501`).*

---

## 🔬 CLI Training & Research Commands

### A. Quick Baseline Demo Run
```powershell
python -m netsentry.train --demo --fast
```

### B. Train Specific Algorithms with Cross-Validation
```powershell
python -m netsentry.train --demo --models lightgbm xgboost random_forest_500 decision_tree --fast
```

### C. Train on Authentic CIC-IDS2017 Dataset
```powershell
python -m netsentry.train --data data\sample\cicids2017_sample.csv --label-column Label --positive-label DoS --fast --artifacts-dir artifacts\cic_run
```

### D. Score New Flows (Live Flow Inference)
```powershell
python -m netsentry.predict --data data\sample\demo_flows.csv --model artifacts\best_model.joblib --features artifacts\feature_names.json --output artifacts\predictions.csv --threshold 0.50
```

### E. Run Full Multi-Model & Research Benchmark Suite
```powershell
python artifacts\run_full_phase3_benchmark.py
```

---

## 📁 Repository Directory Structure

```
netsentry-ai/
├── app/                              # Streamlit Executive Research Web UI
│   ├── main.py                       # Main application entrypoint
│   ├── styles.py                     # Cyberpunk dark navy CSS & custom KPI widgets
│   └── views/                        # 8 Modular UI views
│       ├── overview.py               # Operations Center & Threat Telemetry KPIs
│       ├── explorer.py               # Dataset Explorer, schemas, & DCN glossary
│       ├── model_lab.py              # Interactive 11-model training & tuning
│       ├── evaluation.py             # Confusion matrices, ROC/PR, & threshold sweep
│       ├── traffic_analyzer.py       # Live flow scoring, PCAP ingestion, & SOC diagnosis
│       ├── explainability.py         # Global MDI/permutation & local z-score XAI
│       ├── research.py               # Cross-dataset, zero-day anomaly, & drift workbench
│       └── learn.py                  # DCN + ML curriculum (Packets, TCP, Accuracy Trap)
├── data/
│   ├── sample/                       # Curated authentic benchmark datasets
│   │   ├── cicids2017_sample.csv     # Genuine CIC-IDS2017 sample (5,000 flows)
│   │   ├── unsw_nb15_sample.csv      # Genuine UNSW-NB15 sample (5,000 flows)
│   │   ├── demo_flows.csv            # Synthetic flow baseline
│   │   └── test_traffic.pcap         # Sample 8-packet PCAP for flow extraction
│   └── real/                         # User-provided captures (Git-ignored)
├── docs/                             # Complete Academic & Engineering Documentation
│   ├── technical_architecture.md     # In-depth DCN + ML architecture specification
│   ├── beginner_guide.md             # Student-friendly guide & 10 interview Q&As
│   ├── dataset_provenance.md         # SHA-256 hashes, source URLs, and schemas
│   ├── model_comparison_report.md    # 11-algorithm benchmark across latency & size
│   ├── scientific_evaluation_report.md # Metrics, alert fatigue, and threshold tuning
│   ├── cross_dataset_generalization_report.md # Domain shift results (CIC <-> UNSW)
│   ├── limitations_and_future_work.md# Line-rate 10Gbps boundaries and eBPF roadmap
│   ├── research_paper_outline.md     # Academic research paper with genuine findings
│   └── resume_bullet_points.md       # 3 verified, metrics-driven resume bullets
├── src/netsentry/                    # Core Python Package
│   ├── data/                         # Loading, schema detection, partitioning
│   ├── models/                       # Model factory (11 algorithms + param grids)
│   ├── training/                     # Leakage-free training, CV, tuning, tracking
│   ├── evaluation/                   # Scientific metrics & majority Zero-R baseline
│   ├── explainability/               # Feature importance & plain-English narratives
│   ├── research/                     # Cross-dataset, zero-day anomaly, drift
│   ├── pcap/                         # 5-tuple bidirectional PCAP flow aggregator
│   ├── data.py                       # Backward-compatible data wrapper
│   ├── train.py                      # Enhanced CLI training runner
│   └── predict.py                    # Enhanced CLI flow scoring engine
├── tests/                            # Automated 22-Test Suite
│   ├── test_data.py                  # Tests data validation & partitioning
│   ├── test_models.py                # Tests model factory & pipeline fitting
│   ├── test_evaluation.py            # Tests metrics, baseline, & thresholding
│   ├── test_explainability.py        # Tests feature importance & narratives
│   ├── test_research.py              # Tests cross-dataset, anomaly, & drift
│   ├── test_predict.py               # Tests inference scoring & risk tiers
│   ├── test_pcap.py                  # Tests bidirectional PCAP flow extraction
│   └── test_ui.py                    # Tests compilation of all 8 Streamlit views
├── artifacts/                        # Serialized models, metrics, and comparisons
│   ├── full_benchmark_results.json   # Authentic Phase 3-5 benchmark results
│   └── best_model.joblib             # Active champion model pipeline
├── requirements.txt                  # Python dependencies
└── pyproject.toml                    # Package metadata & build specifications
```

---

## 📚 Complete Documentation Suite

1. [Technical Architecture Specification](docs/technical_architecture.md)
2. [Beginner Guide & Interview Defense Q&A](docs/beginner_guide.md)
3. [Dataset Provenance, Schemas & Checksums](docs/dataset_provenance.md)
4. [Model Comparison & Benchmark Report](docs/model_comparison_report.md)
5. [Scientific Evaluation & Alert Fatigue Report](docs/scientific_evaluation_report.md)
6. [Cross-Dataset Generalization & Domain Shift](docs/cross_dataset_generalization_report.md)
7. [Limitations & Future Work](docs/limitations_and_future_work.md)
8. [Academic Research Paper Outline](docs/research_paper_outline.md)
9. [Resume Bullet Points & Oral Defense Guide](docs/resume_bullet_points.md)
10. [Troubleshooting Guide](docs/troubleshooting.md)

---

## ⚖️ Ethical Notice & Security Guidelines

NetSentry AI is designed strictly for authorized security research, educational demonstrations, and defense. Never inspect or monitor network traffic from devices or networks without explicit, documented authorization.
