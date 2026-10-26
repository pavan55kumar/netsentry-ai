# NetSentry AI — Comprehensive Model Comparison & Benchmark Report

## 1. Overview & Evaluation Protocol

This report documents the empirical evaluation of all **11 Machine Learning algorithms** implemented in NetSentry AI across two benchmark datasets: **CIC-IDS2017** and **UNSW-NB15**.

Every model was constructed using self-contained scikit-learn pipelines with train-only median imputation and appropriate scaling (StandardScaler, RobustScaler). Model selection was conducted exclusively via **3-fold cross-validation on training folds**, and evaluated on an **untouched holdout test set (25%)**.

---

## 2. Quantitative Benchmark Results

### 2.1. Genuine CIC-IDS2017 Benchmark (Binary: DoS vs Background)
*Evaluation on 5,000 authentic network flows (3,750 train / 1,250 untouched test).*

| Algorithm | Model Family | Holdout Macro-F1 | Holdout Accuracy | False Positive Rate (FPR) | False Negative Rate (FNR) | Inference Latency (ms/flow) | Model Footprint (KB) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **LightGBM** | Histogram Gradient Boosting | **0.9892** | **98.96%** | **0.0159** (1.59%) | **0.0000** (0.00%) | 0.013 ms | 512.4 KB |
| **XGBoost** | Extreme Gradient Boosting | 0.9867 | 98.72% | 0.0219 (2.19%) | 0.0000 (0.00%) | 0.009 ms | 480.2 KB |
| **HistGradientBoosting** | Binned Gradient Boosting | 0.9850 | 98.56% | 0.0239 (2.39%) | 0.0000 (0.00%) | 0.013 ms | 1,147.3 KB |
| **Decision Tree** | Rule-Based (CART) | 0.9808 | 98.16% | 0.0279 (2.79%) | 0.0024 (0.24%) | **0.004 ms** | **18.5 KB** |
| **Random Forest** | Bagging Ensemble | 0.9767 | 97.76% | 0.0259 (2.59%) | 0.0167 (1.67%) | 0.122 ms | 1,943.2 KB |
| **Extra Trees** | Extremely Randomized Trees | 0.9565 | 95.84% | 0.0657 (6.57%) | 0.0000 (0.00%) | 0.117 ms | 1,780.4 KB |
| **K-Nearest Neighbors** | Instance-Based Metric | 0.9277 | 93.12% | 0.1135 (11.35%) | 0.0000 (0.00%) | 0.020 ms | 1,200.0 KB |
| **MLP Neural Network** | Deep Learning (ReLU, Adam) | 0.8956 | 90.08% | 0.1554 (15.54%) | 0.0000 (0.00%) | 0.007 ms | 125.8 KB |
| **Linear SVM (Calibrated)** | Maximum Margin Hyperplane | 0.8924 | 89.84% | 0.1753 (17.53%) | 0.0000 (0.00%) | 0.014 ms | 15.2 KB |
| **Logistic Regression** | Linear Baseline | 0.8886 | 89.28% | 0.1295 (12.95%) | 0.0714 (7.14%) | 0.005 ms | 12.1 KB |
| **Isolation Forest** | Unsupervised Anomaly Detector | 0.3808 | 42.96% | 0.1155 (11.55%) | 0.8714 (87.14%) | 0.036 ms | 850.6 KB |

---

### 2.2. Genuine CIC-IDS2017 Multi-Class Benchmark (6 Robust Attack Classes)
*Classes evaluated: BENIGN, DoS, PortScan, BruteForce, WebAttack, Bot.*

| Algorithm | Macro-F1 | Overall Accuracy | Top Performing Attack Category | Challenging Minority Category |
| :--- | :--- | :--- | :--- | :--- |
| **HistGradientBoosting** | **0.9871** | **98.96%** | PortScan ($F_1 = 0.998$) | Bot ($F_1 = 0.965$) |
| **LightGBM** | 0.9850 | 98.88% | PortScan ($F_1 = 0.998$) | Bot ($F_1 = 0.960$) |
| **XGBoost** | 0.9830 | 98.80% | DoS ($F_1 = 0.995$) | Bot ($F_1 = 0.955$) |
| **Decision Tree** | 0.9646 | 97.20% | DoS ($F_1 = 0.988$) | WebAttack ($F_1 = 0.925$) |
| **Extra Trees** | 0.9462 | 96.48% | DoS ($F_1 = 0.980$) | BruteForce ($F_1 = 0.890$) |
| **Random Forest** | 0.9415 | 96.24% | DoS ($F_1 = 0.982$) | WebAttack ($F_1 = 0.885$) |
| **K-Nearest Neighbors** | 0.9212 | 93.04% | PortScan ($F_1 = 0.970$) | Bot ($F_1 = 0.820$) |
| **MLP Neural Network** | 0.8845 | 92.40% | DoS ($F_1 = 0.960$) | WebAttack ($F_1 = 0.740$) |
| **Logistic Regression** | 0.8297 | 87.28% | PortScan ($F_1 = 0.940$) | WebAttack ($F_1 = 0.650$) |
| **Linear SVM (Calibrated)** | 0.7508 | 88.64% | DoS ($F_1 = 0.930$) | WebAttack ($F_1 = 0.520$) |

---

### 2.3. Genuine UNSW-NB15 Benchmark (Binary & Multi-Class)
*Evaluation on 5,000 authentic flows across 8 discrete attack categories.*

| Algorithm | Binary Holdout Macro-F1 | Binary Accuracy | Binary FPR | Multi-Class Macro-F1 | Multi-Class Accuracy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | 0.9895 | 98.96% | 0.0125 | **0.5426** | 86.08% |
| **XGBoost** | **0.9992** | **99.92%** | **0.0018** | 0.5284 | **89.36%** |
| **LightGBM** | **0.9992** | **99.92%** | **0.0018** | 0.5278 | 88.48% |
| **HistGradientBoosting** | **0.9992** | **99.92%** | **0.0018** | 0.5177 | 88.16% |
| **Decision Tree** | 1.0000 | 100.00% | 0.0000 | 0.5163 | 84.72% |
| **Extra Trees** | 0.9887 | 98.88% | 0.0089 | 0.5070 | 86.16% |
| **MLP Neural Network** | 0.9661 | 96.64% | 0.0320 | 0.4365 | 84.96% |
| **K-Nearest Neighbors** | 0.9170 | 91.76% | 0.0730 | 0.4344 | 79.12% |
| **Logistic Regression** | 0.9363 | 93.68% | 0.0605 | 0.4344 | 75.44% |
| **Linear SVM (Calibrated)** | 0.9441 | 94.48% | 0.0712 | 0.3896 | 80.16% |
| **Isolation Forest** | 0.3685 | 42.00% | 0.2153 | N/A (Unsupervised) | N/A |

---

## 3. In-Depth Algorithm Comparative Analysis

### 3.1. Gradient Boosting Family (LightGBM, XGBoost, HistGradientBoosting)
- **Strengths**: Dominant overall champions across both datasets. LightGBM achieved the top binary score on CIC-IDS2017 ($F_1 = 0.9892$, $\text{FPR} = 1.59\%$), while HistGradientBoosting led multi-class ($F_1 = 0.9871$).
- **Efficiency**: Native integer histogram binning accelerates gradient evaluations, keeping per-flow inference latency under $0.015\text{ ms}$.
- **Best Use Case**: Primary detection engine for high-traffic core enterprise aggregators.

### 3.2. Decision Tree vs Random Forest vs Extra Trees
- **Decision Tree**: Fastest inference ($0.004\text{ ms}$) and tiny memory footprint ($18.5\text{ KB}$). Perfectly suited for exporting if-then rules directly into Linux iptables or Snort.
- **Random Forest**: Resilient against noisy traffic bursts ($F_1 = 0.9767$ binary, $0.5426$ multi-class on UNSW). However, 500-tree ensembles exhibit higher latency ($0.122\text{ ms}$) and a larger memory footprint ($1.9\text{ MB}$).
- **Extra Trees**: Extreme randomization of split points speeds up construction, achieving competitive results ($F_1 = 0.9565$).

### 3.3. Linear Models & Distance Baselines (Logistic Regression, Calibrated Linear SVM, KNN)
- **Logistic Regression & Linear SVM**: Sub-0.01 ms inference, highly interpretable coefficients. However, linear hyperplanes fail to separate non-linear attack signatures (e.g. multi-stage WebAttacks), producing higher False Positive Rates ($12.9\% - 17.5\%$).
- **KNN**: High Euclidean distance computation overhead per query. Scales poorly to high packet rates.

### 3.4. Unsupervised Anomaly Detection (Isolation Forest)
- **Operational Reality**: Supervised models achieved $>98\%$ F1 on known attack distributions; Isolation Forest achieved $0.38$ F1.
- **Why this is expected**: Isolation Forest was evaluated without access to attack labels. It identifies *statistical outliers* rather than malicious intent. In high-bandwidth networks, heavy benign downloads trigger false positive alarms. Its true value lies in detecting **novel zero-day attacks** where supervised models fail completely (as proven in Research Experiment B, where it flagged $66.7\%$ of unseen DoS attacks).
