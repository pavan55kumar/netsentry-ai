# NetSentry AI — Phase 5 Independent Research Audit & Finalization Report

**Project**: NetSentry AI v2.0  
**Target Profile**: 3rd-Year B.Tech Information Science and Engineering (ISE) Student Portfolio, Technical Interviews, and Academic Publication  
**Audit Date**: October 26, 2026  
**Auditor**: Independent ML & Cybersecurity Research QA  
**Baseline Git Commit**: `d7cc6ee` (tagged `phase4-complete`)  
**Status**: All 5 Phase 5 Objectives Independently Verified, Benchmarked, and Documented

---

## 1. Objective 1: Independent Reproduction of Results

We audited the entire codebase, environment, test suite, and research experiment scripts starting from clean working tree at commit `d7cc6ee`.

### 1.1. Execution Environment & Dependencies
- **Operating System**: Windows 11 (64-bit)
- **Python Runtime**: Python 3.12.3 in virtual environment (`.\.venv\Scripts\python.exe`)
- **Key Dependencies**:
  - `scikit-learn` == 1.6.1
  - `pandas` == 2.2.3
  - `numpy` == 2.2.3
  - `lightgbm` == 4.6.0
  - `xgboost` == 2.1.4
  - `scapy` == 2.6.1
  - `joblib` == 1.4.2
  - `streamlit` == 1.42.1
- **Random Seeds Tested**: $42$ (primary benchmark), $101, 7, 2024, 999$ (stability audit).

### 1.2. Test Suite Reproduction
- **Command Executed**: `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`
- **Measured Outcome**: **23 out of 23 unit and integration tests passed synchronously in 4.837 seconds (0 failures, 0 errors)**.
- **Coverage**: Preprocessing leakage checks, schema family detection, temporal/stratified splits, model pipelines, operational latency/size profilers, local $z$-score attributions, PCAP flow aggregators, cross-dataset transfers, joint domain training, and Streamlit view compilation.

### 1.3. Generalization Study Reproduction
- **Script Executed**: `.\.venv\Scripts\python.exe artifacts/run_generalization_experiments.py`
- **Output Comparison**: Newly produced values matched [generalization_study_results.json](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/artifacts/generalization_study_results.json) exactly:
  - Config 1 Baseline Cross F1 (CIC $\to$ UNSW): **0.3102** (Acc: 0.4496)
  - Config 2 Unit-Corrected Duration F1: **0.3098** (Acc: 0.4488)
  - Config 4 Morphological Ratios F1: **0.3136** (Acc: 0.4208)
  - Config 6 Joint Multi-Domain Training: **0.9322 on CIC test**, **0.8938 on UNSW test**.

---

## 2. Objective 2: Audit of Experimental Validity

### 2.1. Duplicate and Near-Duplicate Flow Audit
A common flaw in academic intrusion detection literature is train/test data contamination caused by duplicate flows (e.g. repeated NTP heartbeats or retransmitted TCP SYNs). We performed an audit across both datasets:

| Dataset | Total Rows | Exact Raw Duplicates | Overlapping Feature Vectors Between Train & Test (`keep_all`) | Overlap Under `remove_exact` |
| :--- | :--- | :--- | :--- | :--- |
| **CIC-IDS2017** | 5,000 | **785** (15.7%) | **109** (2.18%) | **0 (0.00%)** |
| **UNSW-NB15** | 5,000 | **0** (0.0%) | **0** (0.00%) | **0 (0.00%)** |

#### Deduplication Performance Impact on CIC-IDS2017:
- **`keep_all`** (109 overlapping vectors permitted across split): Macro-F1 $= 0.9733$.
- **`remove_exact`** (duplicate vectors pruned prior to partition, 4,214 flows remaining, 0 overlap): Macro-F1 $= \mathbf{0.9848}$.
- **Finding**: Removing redundant duplicate flows improves generalization by preventing tree models from overfitting to repeated connection bursts.

### 2.2. Preprocessing, Feature Selection & Threshold Leakage Audit
- **Pipeline Encapsulation**: In [factory.py](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/src/netsentry/models/factory.py), `SimpleImputer` and `StandardScaler` / `RobustScaler` reside strictly inside each model's scikit-learn `Pipeline`. Scalers are fitted exclusively on training folds ($X_{train}$), eliminating preprocessing leakage.
- **Champion Model Selection**: In [pipeline.py:L251-254](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/src/netsentry/training/pipeline.py#L251-L254), champion selection is governed strictly by training cross-validation: `best_name = max(results, key=lambda n: results[n].cv_macro_f1_mean)`. The holdout test set was **never** used to select the champion.
- **Decision Threshold Optimization**: In [run_full_phase3_benchmark.py:L270-285](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/artifacts/run_full_phase3_benchmark.py#L270-L285), threshold sweeps operate strictly on a validation partition (`X_val, y_val`) carved out of training data.

### 2.3. Capture-Specific Artifacts & Target Leakage
- `detect_target_leakage()` in [preprocessor.py](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/src/netsentry/data/preprocessor.py) strips surrogate identifiers (`Flow ID`, `Timestamp`, `Source IP`, `Destination IP`, `attack_cat`, `label`) prior to training.
- **Observation**: In CIC-IDS2017, port numbers were excluded from feature matrices to prevent models from memorizing that attacks occurred on port 80. In UNSW-NB15, transport protocol flags and rate features govern decisions without host identity leakage.

---

## 3. Objective 3: Rigorous Generalization & Statistical Evaluation

We executed [artifacts/run_phase5_audit_experiments.py](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/artifacts/run_phase5_audit_experiments.py) and serialized full metrics to `artifacts/phase5_audit_results.json`.

### 3.1. Detailed Multi-Class Confusion Matrices & Per-Class Metrics

#### A. Authentic CIC-IDS2017 (HistGradientBoosting on 6 Classes):
- **Overall Accuracy**: $98.80\%$ | **Macro-F1**: $0.9831$ | **Balanced Accuracy**: $0.9851$

```
Confusion Matrix (Rows = True Label, Columns = Predicted Label):
                  BENIGN   Bot   BruteForce   DoS   PortScan   WebAttack
BENIGN              [495     3            0     3          1           0]
Bot                 [  1    43            0     0          0           0]
BruteForce          [  1     0           60     0          0           0]
DoS                 [  3     0            0   416          0           1]
PortScan            [  1     0            0     0        174           0]
WebAttack           [  1     0            0     0          0          47]
```

| Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
| **BENIGN** | 0.9861 | 0.9861 | 0.9861 | 502 |
| **Bot** | 0.9348 | 0.9773 | 0.9556 | 44 |
| **BruteForce** | 1.0000 | 0.9836 | 0.9917 | 61 |
| **DoS** | 0.9928 | 0.9905 | 0.9917 | 420 |
| **PortScan** | 0.9943 | 0.9943 | 0.9943 | 175 |
| **WebAttack** | 0.9792 | 0.9792 | 0.9792 | 48 |

#### B. Authentic UNSW-NB15 (Random Forest on 10 Classes):
- **Overall Accuracy**: $87.60\%$ | **Macro-F1**: $0.5184$ | **Balanced Accuracy**: $0.4948$

```
Confusion Matrix (Rows = True Label, Columns = Predicted Label):
              Normal  Analysis  Backdoor  DoS  Exploits  Fuzzers  Generic  Recon  Shellcode  Worms
Normal         [ 557         0         0    0         3        2        0      0          0      0]
Analysis       [   1         0         1    2         5        1        0      0          0      0]
Backdoor       [   0         1         1    2         5        0        0      0          0      0]
DoS            [   0         0         0   15        38        4        3      2          0      0]
Exploits       [   0         8         2   20       127        8        2      2          0      0]
Fuzzers        [   3         1         0    1        12       74        1      0          0      0]
Generic        [   0         0         0    0         6        0      280      0          0      0]
Reconnaissance [   0         0         0    3        10        1        0     39          0      0]
Shellcode      [   0         0         0    0         1        0        0      3          2      0]
Worms          [   0         0         0    1         0        0        0      0          0      0]
```

| Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
| **Normal** | 0.9929 | 0.9911 | 0.9920 | 562 |
| **Analysis** | 0.0000 | 0.0000 | 0.0000 | 10 |
| **Backdoor** | 0.2500 | 0.1111 | 0.1538 | 9 |
| **DoS** | 0.3409 | 0.2419 | 0.2830 | 62 |
| **Exploits** | 0.6135 | 0.7515 | 0.6755 | 169 |
| **Fuzzers** | 0.8222 | 0.8043 | 0.8132 | 92 |
| **Generic** | 0.9790 | 0.9790 | 0.9790 | 286 |
| **Reconnaissance** | 0.8478 | 0.7358 | 0.7879 | 53 |
| **Shellcode** | 1.0000 | 0.3333 | 0.5000 | 6 |
| **Worms** | 0.0000 | 0.0000 | 0.0000 | 1 |

> **Critical Scientific Insight**: In UNSW-NB15, rare minority categories (`Analysis`, `Backdoor`, `Worms`) are frequently misclassified as `Exploits` or `DoS`. This explains why the Macro-F1 is $0.5184$ despite a high overall accuracy of $87.60\%$. This is an authentic reflection of intrusion complexity, not a flaw.

---

### 3.2. Alert Volume & The Base-Rate Fallacy in Practice
To demonstrate why low False Positive Rates alone do not prevent SOC alert fatigue, we simulated operational alert volume on a **10 Gbps core link processing 100,000 flows/sec ($8.64\text{ billion flows/day}$)** using our binary champion model (Recall $= 99.76\%$, $\text{FPR} = 1.59\%$):

$$\text{Alert Precision } P(\text{Attack} \mid \text{Alert}) = \frac{\text{Recall} \cdot P(A)}{\text{Recall} \cdot P(A) + \text{FPR} \cdot (1 - P(A))}$$

| Network Attack Prevalence $P(A)$ | True Positive Rate (Recall) | False Positive Rate (FPR) | Alert Precision $P(\text{Attack} \mid \text{Alert})$ | False Alarms as % of All Alerts | Daily True Intrusion Alerts | Daily False Alarm Alerts |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **0.010% (1 in 10,000)** | 99.76% | 1.59% | **0.6%** | **99.4%** | 861,926 | **137,362,262** |
| **0.100% (1 in 1,000)** | 99.76% | 1.59% | **5.9%** | **94.1%** | 8,619,264 | **137,238,624** |
| **1.000% (1 in 100)** | 99.76% | 1.59% | **38.8%** | **61.2%** | 86,192,640 | **136,002,240** |
| **5.000% (1 in 20)** | 99.76% | 1.59% | **76.8%** | **23.2%** | 430,963,200 | **130,507,200** |

> **Key Finding**: In realistic networks where malicious traffic is $\le 0.1\%$, **over 94% of alerts displayed to analysts are false alarms**, despite the model having an apparently stellar $99.76\%$ recall and $1.59\%$ FPR! This mathematically justifies our implementation of validation-based threshold calibration to suppress false alarms.

---

### 3.3. Repeated-Seed Stability Analysis (5 Random Seeds)
We trained models across 5 distinct random seeds ($42, 101, 7, 2024, 999$) to verify that benchmark results are statistically stable:
- **CIC-IDS2017 Binary (Random Forest)**:
  - Macro-F1 across 5 seeds: **$0.9822 \pm 0.0054$** (Range: $0.9733$ to $0.9900$)
- **UNSW-NB15 Binary (Random Forest)**:
  - Macro-F1 across 5 seeds: **$0.9919 \pm 0.0023$** (Range: $0.9879$ to $0.9943$)
- **Joint Multi-Domain Generalization (Across 5 Seeds)**:
  - Tested on untouched CIC test set: **$0.9425 \pm 0.0061$**
  - Tested on untouched UNSW test set: **$0.9003 \pm 0.0052$**

---

### 3.4. Systematic Unseen Zero-Day Attack Discovery Benchmark
We performed holdout experiments across 6 attack families to evaluate supervised vs unsupervised anomaly detection:

| Held-Out Attack Family | Dataset | Sample Size | Supervised Recall on Novel Attack | Unsupervised Recall (Isolation Forest) | Supervised Benign FPR | Unsupervised Benign FPR |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DoS** | CIC-IDS2017 | 1,680 flows | **0.0%** (Blind) | **66.7%** (Detected 2/3) | 2.1% | 9.0% |
| **PortScan** | CIC-IDS2017 | 701 flows | **0.0%** (Blind) | **0.0%** (Below density threshold) | 1.0% | 10.4% |
| **BruteForce** | CIC-IDS2017 | 244 flows | **0.0%** (Blind) | **0.0%** | 1.6% | 11.4% |
| **Generic** | UNSW-NB15 | 1,146 flows | **100.0%** (Shared morphology) | **68.9%** | 0.0% | 15.2% |
| **Exploits** | UNSW-NB15 | 676 flows | **100.0%** (Shared morphology) | **13.0%** | 0.0% | 7.6% |
| **Fuzzers** | UNSW-NB15 | 368 flows | **100.0%** (Shared morphology) | **18.2%** | 0.0% | 10.3% |

> **Key Theoretical Insight**:
> 1. Supervised classifiers trained without DoS completely failed ($0.0\%$ recall) because volumetric DoS attacks produce feature signatures unlike any other attack.
> 2. Unsupervised Isolation Forest flagged **66.7% of novel DoS attacks** because volumetric bursts create geometric outliers in feature space without needing prior labels.
> 3. However, low-packet attacks (`PortScan`, `BruteForce`) did not trigger outlier splits in Isolation Forest, demonstrating that unsupervised anomaly detection cannot guarantee universal zero-day detection.

---

## 4. Deliverables Created in Phase 5

1. [PHASE5_FINAL_AUDIT.md](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/docs/PHASE5_FINAL_AUDIT.md): This comprehensive forensic audit report.
2. [RESEARCH_LIMITATIONS.md](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/docs/RESEARCH_LIMITATIONS.md): Candid, publication-grade analysis of domain shift, false-positive costs, payload blindness, and hardware constraints.
3. [DEMO_CHECKLIST.md](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/docs/DEMO_CHECKLIST.md): Step-by-step interview demonstration checklist, troubleshooting steps, and explanation scripts.
4. Updated [INTERVIEW_PREPARATION.md](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/docs/INTERVIEW_PREPARATION.md): Fully aligned with Phase 5 verified experimental findings.
5. [artifacts/phase5_audit_results.json](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/artifacts/phase5_audit_results.json): Structured empirical metrics for all Phase 5 audit runs.

---

## 5. Verification Commands for the Student

```powershell
# 1. Activate Virtual Environment
.\.venv\Scripts\Activate.ps1

# 2. Run All 23 Automated Verification Tests
python -m unittest discover -s tests -v

# 3. Re-run Phase 5 Comprehensive Audit Experiments
python artifacts\run_phase5_audit_experiments.py

# 4. Score Real Offline PCAP Flows
python -m netsentry.predict --data data\sample\demo_flows.csv --model artifacts\best_model.joblib --features artifacts\feature_names.json --output artifacts\predictions.csv --threshold 0.50

# 5. Launch the Operations Center Web Interface
streamlit run app/main.py
```
