# NetSentry AI — Installation, Environment Setup & Deployment Guide

**Target Audience:** Information Science & Engineering Students, Academic Evaluators, Technical Interviewers  
**Platform Version:** NetSentry AI v2.1.0 (Phase 8 Production-Quality Application)  
**Supported Python Runtimes:** Python 3.10, 3.11, 3.12 (Tested on Python 3.12.3 Windows 64-bit AMD64)  
**Verification Baseline:** 56 / 56 Unit & Integration Tests Passing  

---

## 1. System & Hardware Prerequisites

Before installing NetSentry AI, ensure your host environment satisfies the following minimum operational requirements:

| Component | Minimum Specification | Recommended Specification | Notes |
| :--- | :--- | :--- | :--- |
| **Operating System** | Windows 10/11 (64-bit), Ubuntu 22.04+, macOS 12+ | Windows 11 (64-bit) / Linux x86_64 | Native support across PowerShell and POSIX shells |
| **Python Runtime** | Python 3.10.x | Python 3.12.x | Tested under Python 3.12.3 |
| **CPU Architecture** | 4 Logical Cores (x86_64) | 8+ Logical Cores | Parallel cross-validation & tree ensemble training |
| **System Memory (RAM)** | 4 GB | 8 GB to 16 GB | Required for in-memory processing of multi-megabyte CSVs |
| **Disk Storage** | 2 GB Free Disk Space | 5 GB Free Disk Space | Virtualenv, wheel cache, models, and sample datasets |
| **Packet Capture Tools** | None required for offline CSV | Npcap / Wireshark (Optional) | User-space Scapy handles offline `.pcap` files out of the box |

> [!NOTE]
> **No External C++ Compilers or Cloud Services Required:**
> All 11 machine learning algorithms (Logistic Regression, Decision Trees, Random Forest, Extra Trees, AdaBoost, Gradient Boosting, HistGradientBoosting, LightGBM, XGBoost, Isolation Forest) install pre-compiled binary wheels via `pip`. No paid cloud subscriptions or proprietary software licenses are necessary.

---

## 2. Step-by-Step Installation & Setup

Execute the following commands from your terminal. Ensure your current working directory is the NetSentry AI repository root.

### 2.1 Clone or Open the Repository
```powershell
# Windows PowerShell
cd c:\path\to\netsentry-ai
```
```bash
# Linux / macOS Bash
cd /path/to/netsentry-ai
```

### 2.2 Create an Isolated Virtual Environment
Using a virtual environment isolates project dependencies from your system-wide Python packages, preventing version collisions.

```powershell
# Windows PowerShell
python -m venv .venv
```
```bash
# Linux / macOS
python3 -m venv .venv
```

### 2.3 Activate the Virtual Environment
```powershell
# Windows PowerShell
# If script execution is restricted, temporarily bypass for the active process:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```
```bash
# Linux / macOS
source .venv/bin/activate
```
*Your prompt should now display `(.venv)`.*

### 2.4 Upgrade Package Installer and Install Dependencies
```powershell
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e .
```

#### What is installed:
- `pandas` & `numpy`: High-performance tabular flow manipulation and vector math.
- `scikit-learn`: Linear classifiers, tree ensembles, isolation forest, pipelines, and evaluators.
- `lightgbm` & `xgboost`: Gradient boosted decision tree frameworks.
- `joblib`: Model serialization and parallel cross-validation.
- `scapy`: Offline network packet inspection and 5-tuple flow aggregation.
- `shap`: Shapley Additive Explanations for local and global model interpretability.
- `streamlit` & `plotly`: Interactive security operations dashboard and web interface.

---

## 3. Pre-Flight Quality Gates & Test Suite Verification

Before launching the web interface or demonstrating the system in an interview, run the automated test suite to ensure that all modules, models, and security policies are operational.

### 3.1 Execute Full Test Suite
```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

**Expected Test Output:**
```
Ran 56 tests in ~18s
OK
```
All 56 unit and integration tests must pass:
- 30 baseline ML and DCN unit tests (data splitting, target leakage, metrics, training pipelines).
- 17 security, robustness, PCAP, and safe failure tests (Phase 7 & 7.1).
- 9 end-to-end integration quality gates (Phase 8).

### 3.2 Execute Performance Benchmarks
To independently verify model loading latency, CSV ingestion throughput, and real-time inference speeds on your local CPU:
```powershell
.\.venv\Scripts\python.exe artifacts/run_phase8_performance_benchmarks.py
```
This script generates a machine-readable report at [`artifacts/phase8_performance_results.json`](file:///artifacts/phase8_performance_results.json).

---

## 4. Launching the Web Application

### 4.1 Standard Local Launch
```powershell
.\.venv\Scripts\streamlit.exe run app/main.py
```
Streamlit will initialize the platform and open your default web browser to:
```
Local URL: http://localhost:8501
Network URL: http://<your-lan-ip>:8501
```

### 4.2 Headless / Custom Port Launch
If port 8501 is already occupied or you are running in a restricted sandbox:
```powershell
.\.venv\Scripts\streamlit.exe run app/main.py --server.port 8502 --server.headless true
```

---

## 5. Path Resolution, File Structure & Safe Fallbacks

NetSentry AI employs strict dynamic path resolution. No machine-specific absolute paths (e.g. `C:\Users\username\...`) are hardcoded in the codebase.

```
netsentry-ai/
├── app/                      # Streamlit application UI
│   ├── main.py               # Main navigation router & status sidebar
│   ├── styles.py             # Cybersecurity dark-navy CSS design system
│   └── views/                # Modular application views
│       ├── overview.py       # Operations center & champion model KPI summary
│       ├── explorer.py       # Dataset explorer, schema validator, DCN glossary
│       ├── model_lab.py      # Multi-algorithm training & hyperparameter tuning
│       ├── evaluation.py     # Confusion matrices, ROC/PR, threshold tuning
│       ├── traffic_analyzer.py # Real-time CSV/PCAP flow scoring & quarantine
│       ├── explainability.py # Global XAI (MDI) & local flow SHAP narratives
│       ├── research.py       # Domain shift, zero-day anomaly & robustness workbench
│       └── learn.py          # Educational curriculum (DCN + ML fundamentals)
├── artifacts/                # Trained model pipelines, benchmark results, and metrics
│   ├── best_model.joblib     # Pre-trained champion LightGBM/Tree pipeline
│   ├── feature_names.json    # Trained canonical feature schema
│   ├── metrics.json          # Cross-validation & holdout evaluation metrics
│   └── phase8_performance_results.json # Verified operational latency metrics
├── data/sample/              # Curated flow datasets & test PCAP captures
│   ├── demo_flows.csv        # 1,200 curated flows with 5-tuples and labels
│   ├── test_traffic.pcap     # 8-packet authentic capture for offline ingestion
│   ├── cicids2017_sample.csv # Authentic CIC-IDS2017 multi-attack sample
│   └── unsw_nb15_sample.csv  # Authentic UNSW-NB15 modern attack sample
├── docs/                     # Technical architecture, runbooks, and audits
├── src/netsentry/            # Core Python package
│   ├── data/                 # Ingestion, schema validation, synthetic flows
│   ├── evaluation/           # Threshold tuning, accuracy trap, binary metrics
│   ├── explainability/       # Tree MDI, local attribution, plain-English narrative
│   ├── models/               # Factory pattern for 11 ML algorithms
│   ├── pcap/                 # Scapy 5-tuple flow aggregation & header verification
│   ├── predict.py            # Inference pipeline, risk tiers, quarantine policy
│   ├── research/             # Domain transfer, unsupervised anomaly, robustness
│   ├── train.py              # CLI training driver
│   └── utils/logging.py      # Privacy-preserving logging & IP host octet masking
└── tests/                    # 56 automated unit & integration tests
```

### 5.1 Graceful Fallbacks for Missing Artifacts
- **Missing Trained Model (`artifacts/best_model.joblib`):**
  If the model file is absent, the **Overview**, **Traffic Analyzer**, and **Explainability Lab** views do not crash. They display an informative warning card with a one-click button: `🚀 Run Quick Baseline Demo`. Clicking it trains a clean baseline model in 3 seconds.
- **Missing Dataset Files:**
  If public benchmark datasets have not yet been downloaded, the application automatically falls back to `data/sample/demo_flows.csv` or generates synthetic educational flow vectors using `src/netsentry/data/synthetic.py`.

---

## 6. Security Hygiene, Secrets & Privacy

NetSentry AI adheres to professional security engineering practices:
1. **No Embedded Secrets:** The repository contains zero API keys, passwords, or cloud credentials.
2. **Privacy Masking:** IP host octets are masked in logs and export CSVs (`192.168.1.***`), preserving subnet context while protecting endpoint anonymity.
3. **Quarantine Isolation:** Corrupted flows and non-finite rates ($+\infty, -\infty$) are quarantined (`prediction = -1`, `data_status = INVALID_NON_FINITE`) rather than silently imputed as benign.
4. **Clean `.gitignore`:** Virtual environments (`.venv`), local temp files (`.local-temp/`), private capture files (`*.pcapng`, `data/private/`), and logs (`*.log`) are excluded from Git version control.
