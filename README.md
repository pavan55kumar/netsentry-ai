# NetSentry AI — Advanced ML Research Platform & Cybersecurity UI

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit UI](https://img.shields.io/badge/Streamlit-v2.0-FF4B4B.svg)](https://streamlit.io/)
[![Tests Passing](https://img.shields.io/badge/Tests-15%2F15%20Passing-brightgreen.svg)]()

> **NetSentry AI** is a professional, research-grade Network Intrusion Detection & Anomaly Detection research platform. It bridges **Data Communication & Networking (DCN)** with **Machine Learning (ML)** engineering, training on bidirectional network connection flows (NetFlow / IPFIX).

---

## 🚀 Key Highlights & Architectural Upgrades

- **Multi-Model Benchmark Suite:** Evaluates 9 distinct algorithms across linear (`Logistic Regression`), rule-based (`Decision Tree`), bagging ensembles (`Random Forest`, `Extra Trees`), boosting (`HistGradientBoosting`), distance-based (`KNN`), maximum margin (`Calibrated Linear SVM`), deep learning (`MLP Neural Network`), and unsupervised anomaly discovery (`Isolation Forest`).
- **Zero-Leakage Training Guardrails:** Imputation, standard scaling, and hyperparameter tuning occur strictly inside training cross-validation folds. The holdout test set remains completely untouched until final verification.
- **The Accuracy Trap Safeguard:** Automatically computes a majority Zero-R dummy classifier baseline to expose why naive 99% accuracy can be completely blind to minority cyber attacks.
- **Explainable AI (XAI):** Global Tree MDI / Permutation feature importance, local flow attribution waterfalls ($z$-scores), and plain-English SOC analyst narratives.
- **Advanced Research Features:** Cross-dataset domain generalization (e.g. CIC-IDS2017 to UNSW-NB15), zero-day unsupervised anomaly detection, and simulated covariate model drift.
- **Modular PCAP Ingestion:** Built-in 5-tuple bidirectional flow aggregator parsing `.pcap` and `.pcapng` packet captures into model-ready CSVs.
- **Executive Operations Center UI:** Cyberpunk dark navy Streamlit interface with interactive Plotly charts, threshold calibration sliders, and live flow inference.

---

## 🛠️ Quick Start in VS Code (Windows PowerShell)

### 1. Environment Setup
Open the `netsentry-ai` folder in VS Code, open a terminal (`Terminal → New Terminal`), and run:

```powershell
# If execution policy blocks script activation:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install package with all research dependencies
python -m pip install --upgrade pip
pip install -e .
pip install -r requirements.txt
```

### 2. Run Automated Verification Tests
```powershell
python -m unittest discover -s tests -v
```
*(Runs 15 automated unit and integration tests covering data partitioning, model factory, evaluation metrics, explainability, research experiments, and predictions).*

### 3. Launch the Premium Research Web UI
```powershell
streamlit run app/main.py
```
*(Opens the interactive research interface in your default browser at `http://localhost:8501`).*

---

## 🔬 CLI Training & Prediction Commands

### A. Quick Baseline Demo Run (Synthetic Data)
```powershell
python -m netsentry.train --demo
```
*(Runs 5-fold cross-validation on 4 core algorithms and generates champion artifacts in `artifacts/`).*

### B. Fast Laptop Mode (Sub-second execution)
```powershell
python -m netsentry.train --demo --fast
```

### C. Train All 9 Supported Algorithms
```powershell
python -m netsentry.train --demo --fast --models logistic_regression decision_tree random_forest_500 extra_trees_500 hist_gradient_boosting k_nearest_neighbors support_vector_machine mlp_neural_network isolation_forest
```

### D. Hyperparameter Tuning on Training Folds
```powershell
python -m netsentry.train --demo --tune --fast
```

### E. Train on Real Research Dataset (CIC-IDS2017 Sample)
```powershell
python -m netsentry.train --data data\sample\cicids2017_sample.csv --label-column Label --positive-label "DoS Hulk" --fast --artifacts-dir artifacts\cicids_run
```

### F. Score New Network Flows (Inference)
```powershell
python -m netsentry.predict --data data\sample\demo_flows.csv --model artifacts\best_model.joblib --features artifacts\feature_names.json --output artifacts\predictions.csv --threshold 0.50
```

---

## 📁 Repository Directory Structure

```
netsentry-ai/
├── app/                              # Streamlit Executive Research Web UI
│   ├── main.py                       # Main application entrypoint
│   ├── styles.py                     # Cyberpunk dark navy CSS & custom widgets
│   └── views/                        # 8 Modular UI views
│       ├── overview.py               # Executive Operations Center & KPIs
│       ├── explorer.py               # Dataset Explorer, schemas, & DCN glossary
│       ├── model_lab.py              # Interactive model training & benchmarking
│       ├── evaluation.py             # Confusion matrices, ROC/PR, & threshold slider
│       ├── traffic_analyzer.py       # Live flow scoring, filtering, & SOC diagnosis
│       ├── explainability.py         # Global importance & local waterfall XAI
│       ├── research.py               # Cross-dataset, anomaly, & drift research
│       └── learn.py                  # DCN + ML curriculum (Packets, TCP, Accuracy Trap)
├── data/
│   ├── sample/                       # Curated benchmark research datasets
│   │   ├── cicids2017_sample.csv     # Authentic CIC-IDS2017 schema (Multi-class)
│   │   ├── unsw_nb15_sample.csv      # Authentic UNSW-NB15 schema (Cross-domain)
│   │   └── demo_flows.csv            # Synthetic flow baseline
│   └── real/                         # User-provided public captures (Git-ignored)
├── docs/                             # Academic & Engineering Documentation
│   ├── architecture.md               # Complete DCN + ML architecture guide
│   ├── training_guide.md             # Multi-model training & tuning guide
│   ├── evaluation_guide.md           # Metrics guide & the Accuracy Trap
│   └── troubleshooting.md            # Windows PowerShell & troubleshooting guide
├── src/netsentry/                    # Core Python Package
│   ├── data/                         # Loading, schema validation, splitting
│   ├── models/                       # Model factory (9 algorithms)
│   ├── training/                     # Leakage-free training, CV, tuning, tracking
│   ├── evaluation/                   # Scientific metrics & majority baseline
│   ├── explainability/               # Feature importance & plain-English narratives
│   ├── research/                     # Cross-dataset, anomaly detection, drift
│   ├── pcap/                         # 5-tuple bidirectional PCAP flow extractor
│   ├── data.py                       # Backward-compatible data wrapper
│   ├── train.py                      # Enhanced CLI training runner
│   └── predict.py                    # Enhanced CLI flow scoring engine
├── tests/                            # Automated Unit & Integration Test Suite
│   ├── test_data.py                  # Tests data validation & partitioning
│   ├── test_models.py                # Tests model factory & pipeline fitting
│   ├── test_evaluation.py            # Tests metrics, baseline, & thresholding
│   ├── test_explainability.py        # Tests feature importance & narratives
│   ├── test_research.py              # Tests cross-dataset, anomaly, & drift
│   └── test_predict.py               # Tests inference scoring & risk tiers
├── artifacts/                        # Serialized models, metrics, and comparisons
├── requirements.txt                  # Python dependencies
└── pyproject.toml                    # Package metadata & build specifications
```

---

## 📚 Technical Documentation Links

- [System Architecture & DCN Flow Mechanics](docs/architecture.md)
- [Training Algorithms & Hyperparameter Tuning Guide](docs/training_guide.md)
- [Evaluation Metrics & The Accuracy Trap](docs/evaluation_guide.md)
- [PowerShell & Execution Troubleshooting Guide](docs/troubleshooting.md)

---

## ⚖️ Ethical Notice & Security Research Guidelines

Only capture and analyze network traffic from systems and networks that you own or have explicit, documented authorization to inspect. NetSentry AI is designed exclusively for educational, defensive, and academic research purposes.
