# NetSentry AI — Reproducibility & Research Replication Guide

## 1. Overview and Environment Requirements

This guide provides end-to-end instructions for replicating all benchmarks, model training pipelines, cross-dataset evaluations, robustness stress tests, and security audits reported in NetSentry AI.

### Hardware & Operating System Specifications
- **Operating System:** Windows 10 / 11 (x64) or Linux (Ubuntu 22.04 LTS+)
- **CPU:** Minimum 4 physical cores (Intel Core i5/i7 or AMD Ryzen 5/7 recommended)
- **RAM:** Minimum 8 GB (16 GB recommended for full ensemble training)
- **Disk Space:** ~2 GB for repository, virtual environment, and sample datasets

### Python Runtime Requirements
- **Required Python Version:** Python `3.12.x` (verified on `3.12.3`)
- **Package Manager:** `pip` (bundled with Python)

---

## 2. Environment Setup

### Step 1: Clone Repository & Create Virtual Environment
Open PowerShell (Windows) or Bash (Linux) in the project directory:

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Step 2: Install Verified Dependencies
Install dependencies from `requirements.txt`:

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

Verify installation:
```powershell
python -c "import sklearn, lightgbm, xgboost, scapy, streamlit; print('All core dependencies imported successfully!')"
```

---

## 3. Dataset Acquisition, Licensing & Provenance

NetSentry AI includes curated sample partitions in `data/sample/` so that all experiments, unit tests, and dashboard views run out of the box without requiring external 50 GB downloads.

```
===================================================================================================
                               DATASET PROVENANCE & LICENSING
===================================================================================================
Dataset       Sample Path                     Full Dataset Source              Licensing / Terms
---------------------------------------------------------------------------------------------------
CIC-IDS2017   data/sample/cicids2017_sample.csv   Canadian Institute for Cybersec. Open Academic Research
UNSW-NB15     data/sample/unsw_nb15_sample.csv    UNSW Canberra Cyber (ACCS)       CC BY-NC 4.0
Demo Flows    data/sample/demo_flows.csv          Synthesized canonical flows      MIT License
Sample PCAP   data/sample/test_traffic.pcap       Synthesized offline capture      MIT License
===================================================================================================
```

### Dataset Citations
1. **CIC-IDS2017:**
   - Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSP 2018.
   - Hosted by: University of New Brunswick (UNB), Canada.
2. **UNSW-NB15:**
   - Moustafa, N., & Slay, J. (2015). *UNSW-NB15: a comprehensive dataset for network intrusion detection systems.* Military Communications and Information Systems Conference (MilCIS).
   - Hosted by: Australian Centre for Cyber Security (ACCS), UNSW Canberra.

---

## 4. Exact Reproduction Commands for Major Research Results

Every experiment script is located in `artifacts/` and operates deterministically under fixed random seeds.

### 4.1 Execute Complete Verification Test Suite (63 Tests)
Run all 63 unit, integration, and security tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
- **Expected Outcome:** 63 tests passing, 0 failures, execution time ~14–16 seconds.

---

### 4.2 Reproduce Phase 9 Independent Audit Verification
Run the automated audit script that checks partition disjointness, metrics provenance, PCAP compatibility, and security policies:

```powershell
.\.venv\Scripts\python.exe artifacts/run_phase9_audit_checks.py
```
- **Expected Output File:** `artifacts/phase9_audit_results.json`
- **Expected Status:** `"all_checks_passed": true` (duration ~1.2 seconds).

---

### 4.3 Reproduce Phase 6 Advanced Research Experiments
Trains the 8 baseline algorithms, evaluates 5 unseen attack families (withheld classes), tests 7 cross-domain generalization strategies (CIC-IDS2017 $\to$ UNSW-NB15), and generates forensic error attributions:

```powershell
.\.venv\Scripts\python.exe artifacts/run_phase6_experiments.py
```
- **Expected Output File:** `artifacts/phase6_experiment_results.json`
- **Key Expected Outputs:**
  - `lightgbm.macro_f1`: **0.9892** (Accuracy: 98.96%, FPR: 1.59%)
  - `random_forest_500.macro_f1`: **0.9767** (Accuracy: 97.76%, FPR: 2.59%)
  - `part2_unseen_attack_suite.family_results.DoS`: Supervised Recall: **0.0%**, Isolation Forest Recall: **66.79%**
  - `part3_generalization_strategies.baseline_cross_macro_f1`: **0.3148**
  - `part3_generalization_strategies.strategy_results[7]` (Joint Multi-Domain): **0.8932**

---

### 4.4 Reproduce Phase 7 Robustness Stress Tests
Applies 5 physically grounded perturbations to the champion LightGBM and Random Forest models (clock jitter, missingness, jumbo frames, 100G line-rate bursts, adversarial rate pacing):

```powershell
.\.venv\Scripts\python.exe artifacts/run_phase7_robustness_experiments.py
```
- **Expected Output File:** `artifacts/phase7_robustness_results.json`
- **Key Expected Outputs:**
  - 5% Measurement Jitter: Macro-F1 collapses from **0.9892 to 0.6617** (33.12% predictions flipped; 405 attacks flipped to benign).
  - Enterprise Jumbo Frames (MTU 9000): Macro-F1 collapses to **0.6639** (33.28% flips).
  - 100 Gbps Line-Rate Burst: Macro-F1 remains **0.9850** (0.56% flips).
  - Adversarial Rate Pacing: 4 attacks evade LightGBM; 27 attacks evade Random Forest.

---

### 4.5 Reproduce Phase 5 Multi-Seed Stability & Base-Rate Fallacy Audit
Evaluates 5-seed statistical stability and Bayesian alert fatigue across prevalences:

```powershell
.\.venv\Scripts\python.exe artifacts/run_phase5_audit_experiments.py
```
- **Expected Output File:** `artifacts/phase5_audit_results.json`
- **Key Expected Outputs:**
  - 5-Seed CIC-IDS2017 Random Forest: Macro-F1 **$0.9822 \pm 0.0054$**
  - 5-Seed UNSW-NB15 Random Forest: Macro-F1 **$0.9919 \pm 0.0023$**
  - Alert Fatigue at 0.1% attack prevalence: **94.09% of all alerts are false alarms**.

---

### 4.6 Reproduce Phase 8 Operational Performance Benchmarks
Measures batch throughput, single-flow inference latency, memory footprints, and cold-start import duration:

```powershell
.\.venv\Scripts\python.exe artifacts/run_phase8_performance_benchmarks.py
```
- **Expected Output File:** `artifacts/phase8_performance_results.json`
- **Key Expected Outputs:**
  - Batch Throughput: **> 15,000 flows/sec**
  - Single-Flow Latency: **< 1.0 ms/flow**
  - Model Memory: **< 5 MB**

---

### 4.7 Launch the Interactive SOC Dashboard
Launch the NetSentry AI web application:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app/main.py
```
- Access in browser: `http://localhost:8501`
- Explore:
  - **Overview:** Architecture and executive summary.
  - **Model Lab:** Train and compare 11 algorithms.
  - **Traffic Analyzer:** Real-time scoring and offline PCAP ingestion.
  - **Dataset Explorer:** Flow distributions and class imbalance.
  - **Research Hub:** Concept inversion, unseen attack benchmarks, and robustness reports.
  - **Evaluation & Forensics:** Confusion matrices, ROC/PR curves, and SHAP explanations.

---

## 5. Artifact Provenance Map

```
========================================================================================================
                                  PROVENANCE AND DESTINATION MAP
========================================================================================================
Artifact Path                          Generating Script                Source Dataset
--------------------------------------------------------------------------------------------------------
artifacts/best_model.joblib            run_full_phase3_benchmark.py     demo_flows.csv (8 feats)
artifacts/feature_names.json           run_full_phase3_benchmark.py     demo_flows.csv (8 feats)
artifacts/phase6_experiment_results.json run_phase6_experiments.py      cicids2017 & unsw_nb15 samples
artifacts/phase7_robustness_results.json run_phase7_robustness_exper... cicids2017_sample.csv (77 feats)
artifacts/phase5_audit_results.json    run_phase5_audit_experiments.py  cicids2017 & unsw_nb15 samples
artifacts/phase8_performance_results.json run_phase8_performance_ben... demo_flows.csv (8 feats)
artifacts/phase9_audit_results.json    run_phase9_audit_checks.py       Full repository audit check
========================================================================================================
```

---

## 6. Known Reproducibility Limitations

1. **Subsampled Datasets in Repository:** To maintain a lightweight Git repository suitable for GitHub portfolios and student evaluations, the files in `data/sample/` are 5,000-row stratified subsamples of the original multi-gigabyte PCAP and NetFlow captures. Exact metric values on the 2.8-million-row full CIC-IDS2017 dataset will vary by $\pm 0.005$ due to larger sample support.
2. **PCAP Engine Notice:** Scapy `PcapReader` is an interpreted Python reader designed for offline education and forensic triage. It operates at ~10,000 packets/sec. Reproducing benchmarks on 100 Gbps live wire feeds requires dedicated hardware capture tools (e.g., `tshark` or DPDK ring buffers).
3. **Random State Sensitivity:** Multi-threading in LightGBM and XGBoost (`n_jobs=-1`) can introduce micro-level floating point non-determinism across different CPU microarchitectures (e.g. Intel AVX2 vs AMD Zen). Setting `n_jobs=1` guarantees 100% bitwise determinism at the cost of training duration.
