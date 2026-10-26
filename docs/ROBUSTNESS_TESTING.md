# NetSentry AI — Phase 7 & 7.1: Robustness, Adversarial Perturbation & Distribution-Shift Monograph

**Author:** NetSentry AI Machine Learning Research & Security Engineering Group  
**Dataset Benchmark:** Authentic CIC-IDS2017 Sample (3,750 Training Samples, 1,250 Holdout Test Samples, 77 Features)  
**Evaluated Models:** Champion LightGBM, Random Forest (500 Trees), and Unsupervised Isolation Forest  
**Artifacts Generated:** [`artifacts/phase7_robustness_results.json`](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/artifacts/phase7_robustness_results.json), [`artifacts/run_phase7_robustness_experiments.py`](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/artifacts/run_phase7_robustness_experiments.py)

---

## 1. Research Motivation: Beyond Academic Clean-Data Benchmarks

A pervasive problem in cybersecurity machine learning research is the **Clean-Data Accuracy Illusion**:
A gradient-boosted tree ensemble or deep neural network trained on pre-packaged intrusion datasets (such as CIC-IDS2017 or UNSW-NB15) routinely reports **>98% accuracy and F1-scores**. However, when deployed onto live enterprise networks, these systems experience catastrophic performance degradation.

Real-world enterprise network traffic is subjected to continuous physical disruptions:
1. **Hardware NIC Clock Jitter:** Network interface cards (NICs), hardware timers, and polling drivers experience interrupt latency and thermal clock drift, introducing $\pm 5\text{--}15\%$ noise into packet inter-arrival times.
2. **Telemetry Sampling & Sensor Dropout:** High-speed routers export sampled NetFlow/sFlow packets (e.g. 1 out of 1,000 packets) or suffer buffer exhaustion, causing feature counters to be dropped or unrecorded.
3. **Extreme Enterprise Regimes:** Data center storage networks operate with 9,000-byte jumbo frames, and backbone links burst at 100 Gbps line rates ($1.25 \times 10^{10}\text{ bytes/sec}$).
4. **Adversarial Pacing Manipulation:** Attackers intentionally dilute transmission rates (Low-and-Slow DoS, Slowloris) to evade volumetric burst thresholds.

In Phase 7, we engineered a controlled, reproducible empirical robustness test harness ([`src/netsentry/research/robustness.py`](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/src/netsentry/research/robustness.py)) to quantitatively measure how predictions, F1-scores, false positive rates, and decision boundaries shift under physically defensible perturbations.

---

## 2. Methodology & Physical Plausibility Constraints

### 2.1 Distinguishing Physically Plausible Perturbations from Arbitrary Feature Noise
Many adversarial ML papers generate perturbations using unconstrained mathematical gradients (e.g., $L_\infty$ FGSM) that produce physically impossible network states—such as negative packet counts, negative flow durations, or packet lengths exceeding network layer limits.

In NetSentry AI, every perturbation is constrained by **physical Data Communication and Networking (DCN) invariants**:
- **Non-Negativity Invariant:** Network rates, packet counts, and flow durations cannot be negative:
  $$x_{\text{perturbed}} = \max(x + \delta, 0.0)$$
- **Discrete Counter Invariant:** TCP flag counts (SYN, RST, ACK) and packet numbers are discrete integers; continuous Gaussian noise is restricted strictly to continuous timing and rate features.
- **Maximum Transmission Unit (MTU) Invariant:** Standard Ethernet packets cannot exceed 1,514 bytes; data center jumbo frames cannot exceed 9,000 bytes.

### 2.2 Quantitative Robustness Metrics
For each perturbation experiment, we track:
- **Macro-F1 Delta ($\Delta \text{F1}$):** Change in class-balanced harmonic mean of precision and recall.
- **False Positive Rate Delta ($\Delta \text{FPR}$):** Shift in benign traffic incorrectly flagged as malicious.
- **Prediction Flip Rate (%):** Proportion of test samples whose classification flipped:
  $$\text{Flip Rate} = \frac{1}{N} \sum_{i=1}^N \mathbb{I}\left(\hat{y}_i^{(\text{orig})} \neq \hat{y}_i^{(\text{pert})}\right) \times 100\%$$
- **Directional Flip Breakdown:** Disaggregates malicious-to-benign flips (evasion risk) vs benign-to-malicious flips (false alarm risk).
- **Transformation Verification (`transformation_verified`):** Verifies that the targeted input features were altered ($X_{\text{pert}} \neq X_{\text{orig}}$). If no compatible features exist in the schema, the test is marked `UNSUPPORTED` rather than reporting false immunity.
- **Aggregate Resilience Score:** A composite score $[0, 100]$ penalizing flip rate and F1 degradation.

---

## 3. Empirical Experimental Results (Phase 7.1 Verified)

The complete experiment was executed on the identical test split ($N = 1,250$ holdout flows) using `artifacts/run_phase7_robustness_experiments.py`.

### 3.1 Champion LightGBM Robustness Results
- **Clean Holdout Baseline:** Macro-F1 = **0.9892**, FPR = **1.59%**
- **Aggregate Resilience Score:** **37.2 / 100**

| Perturbation Test | Category | Status | Perturbed F1 | $\Delta \text{F1}$ | Flip Rate (%) | $\Delta \text{FPR}$ | Malicious $\to$ Benign | Benign $\to$ Malicious |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Measurement Jitter (5%)** | `measurement_noise` | COMPLETED | 0.6617 | **-0.3274** | **33.12%** | +0.0080 | **405** | 9 |
| **High Measurement Jitter (15%)** | `measurement_noise` | COMPLETED | 0.6100 | **-0.3792** | **37.84%** | +0.0040 | **465** | 8 |
| **Feature Dropout (10% Missing)** | `missing_features` | COMPLETED | 0.9726 | **-0.0166** | **2.08%** | +0.0100 | 18 | 8 |
| **Severe Feature Dropout (25%)** | `missing_features` | COMPLETED | 0.9072 | **-0.0819** | **8.88%** | +0.0139 | 99 | 12 |
| **Enterprise Jumbo Frames (MTU 9000)** | `extreme_values` | COMPLETED | 0.6639 | **-0.3253** | **33.28%** | -0.0120 | **414** | 2 |
| **100 Gbps Line-Rate Burst** | `extreme_values` | COMPLETED | 0.9850 | **-0.0042** | **0.56%** | +0.0120 | 0 | 7 |
| **Adversarial Low-and-Slow Pacing** | `rate_pacing` | COMPLETED | 0.9833 | **-0.0058** | **0.56%** | +0.0060 | 4 | 3 |

---

### 3.2 Random Forest Ensemble Comparison
- **Clean Holdout Baseline:** Macro-F1 = **0.9767**, FPR = **2.59%**
- **Aggregate Resilience Score:** **34.7 / 100**

| Perturbation Test | Category | Status | Perturbed F1 | $\Delta \text{F1}$ | Flip Rate (%) | $\Delta \text{FPR}$ | Malicious $\to$ Benign | Benign $\to$ Malicious |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Measurement Jitter (5%)** | `measurement_noise` | COMPLETED | 0.6096 | **-0.3671** | **37.60%** | -0.0259 | **470** | 0 |
| **High Measurement Jitter (15%)** | `measurement_noise` | COMPLETED | 0.5867 | **-0.3900** | **39.52%** | -0.0259 | **494** | 0 |
| **Feature Dropout (10% Missing)** | `missing_features` | COMPLETED | 0.9678 | **-0.0090** | **1.52%** | -0.0080 | 19 | 0 |
| **Severe Feature Dropout (25%)** | `missing_features` | COMPLETED | 0.8823 | **-0.0944** | **10.88%** | -0.0179 | 136 | 0 |
| **Enterprise Jumbo Frames (MTU 9000)** | `extreme_values` | COMPLETED | 0.6919 | **-0.2848** | **30.32%** | -0.0199 | **376** | 3 |
| **100 Gbps Line-Rate Burst** | `extreme_values` | COMPLETED | 0.9817 | **+0.0050** | **0.64%** | -0.0100 | 6 | 2 |
| **Adversarial Low-and-Slow Pacing** | `rate_pacing` | COMPLETED | 0.9662 | **-0.0106** | **2.32%** | -0.0120 | 27 | 2 |

---

## 4. In-Depth Root Cause Analysis & Validation Findings (Phase 7.1)

### 4.1 Vulnerability 1: Tree Ensemble Brittleness to Small Measurement Noise
Both LightGBM and Random Forest suffer substantial degradation under continuous measurement jitter ($\Delta \text{F1} = -0.3274$ and $-0.3671$ respectively).
Decision trees partition feature space using orthogonal axis-aligned hyperplanes:
$$\text{If } x_{\text{inter\_arrival\_time}} \le 0.0042 \implies \text{Attack}$$
In network datasets, attacks (such as DoS floods or Port Scans) generate tightly clustered timing distributions. A tree ensemble splits on extremely fine-grained thresholds. When zero-mean Gaussian jitter is applied ($\sigma = 0.05 \cdot \text{std}$), hundreds of attack flows get pushed past the decision boundary into the benign region.

Crucially, **out of 414 flipped predictions in LightGBM, 405 were attacks flipped to benign**. This reveals that small hardware clock variance acts as an accidental evasion mechanism, causing attack recall to drop precipitously.

### 4.2 Resilience 1: Defense Against Sensor Telemetry Dropout
In contrast to continuous noise, both pipelines exhibited remarkable resilience against missing feature values:
- At **10% missing features**, LightGBM retained **0.9726 F1** (only 2.08% flip rate).
- At **25% missing features**, LightGBM retained **0.9072 F1** (8.88% flip rate).

Because our pipeline integrates `SimpleImputer(strategy="median")` inside the trained sklearn Pipeline:
1. When an isolated feature drops out, replacing it with the training median places the sample near the center of the marginal distribution.
2. Because tree ensembles split on multiple orthogonal features (77 features in CIC-IDS2017), the remaining 75% intact features provide sufficient redundant information for the trees to vote correctly.

### 4.3 Resolution of Finding 1: Audit of the "Zero-Change" Reporting Anomaly
During initial Phase 7 execution, three perturbations reported zero flips ($0.00\%$ change):
- Enterprise Jumbo Frames (MTU 9000)
- 100 Gbps Line-Rate Burst
- Adversarial Low-and-Slow Pacing

#### Root Cause: Schema Keyword Mismatch in the Test Harness
The initial test functions in `robustness.py` checked only snake_case demo names (`average_packet_size`, `flow_bytes_per_second`, `flow_duration_ms`). However, the actual benchmark dataset evaluated is **CIC-IDS2017**, which employs Title Case header formats (`Average Packet Size`, `Flow Bytes/s`, `Flow Duration`, `Packet Length Mean`, etc.). Consequently:
1. `col in X_perturbed.columns` evaluated to `False` for all columns.
2. Zero features were modified, meaning the pipeline evaluated identical unaltered baseline inputs.
3. The report erroneously interpreted this lack of input alteration as model "robustness".

#### Remediation Implemented in Phase 7.1:
1. **Flexible Semantic Column Resolution:**
   Introduced `_find_matching_columns()` using regex/case-insensitive substring patterns to resolve relevant features across diverse network datasets (e.g., CIC-IDS2017, UNSW-NB15, NetSentry demo).
2. **Explicit Modification Verification & `status` Tracking:**
   Every perturbation now records `modified_cols`. In `evaluate_single_perturbation()`:
   - If `len(features_perturbed) == 0`, the perturbation is marked `status = "UNSUPPORTED"`, `transformation_verified = False`, and skips prediction rather than reporting false immunity.
   - If features are modified, it mathematically verifies `transformation_verified = (not X_perturbed[features].equals(X_orig[features]))`.
3. **True Empirical Findings After Verification:**
   - **Enterprise Jumbo Frames (MTU 9000):** When 10 packet length and segment size features are correctly scaled to 8,960 bytes, **LightGBM F1 collapses from 0.9892 to 0.6639 with 33.28% flips (414 attacks flipped to benign!)**. Intrusion classifiers heavily rely on packet size distributions to detect attacks. When packets resemble large enterprise bulk transfers, attack signatures are masked.
   - **100 Gbps Line-Rate Burst:** Modifying 4 flow/packet rate columns to line-rate wire speeds produces 7 flips in LightGBM (0.56%) and 8 flips in RF (0.64%). Because rate thresholds saturate at high splits, the models are largely stable, though 7 benign flows trigger false alarms.
   - **Adversarial Low-and-Slow Pacing:** Dilating duration 10x successfully allowed 4 attacks in LightGBM and 27 attacks in Random Forest to evade detection by lowering packet-per-second rates below detection thresholds.

### 4.4 Taxonomy of Tested Perturbations
To ensure research integrity, every perturbation is classified into one of three statuses:
1. **GENUINELY TESTED (`COMPLETED`):**
   - Measurement Jitter (5% and 15%): Fully tested across 65 continuous timing and rate features.
   - Feature Dropout (10% and 25%): Fully tested across all 77 features.
   - Enterprise Jumbo Frames: Fully tested across 10 packet length / segment size features.
   - 100 Gbps Line-Rate Burst: Fully tested across 4 packet and byte rate features.
   - Adversarial Low-and-Slow Pacing: Fully tested across 5 duration and rate features.
2. **UNSUPPORTED:**
   - If a dataset lacks rate or timing features required for a specific perturbation, the harness flags it as `UNSUPPORTED` and does not report a synthetic resilience score.
3. **INCONCLUSIVE:**
   - Perturbations where input modifications altered fewer than 2 relevant features or where feature distributions exhibit zero variance are flagged for manual domain review.

---

## 5. Defense Engineering Recommendations

Based on these empirical findings, we establish the following concrete engineering defenses:

1. **Noise-Augmented Training (Data Perturbation Injection):**
   During training fold generation, inject small $\pm 3\text{--}5\%$ Gaussian jitter into continuous timing features. This forces decision tree split algorithms to select wider, more conservative margins rather than over-specializing on narrow training values.
2. **Feature Quantization / Binning:**
   Discretize continuous timing and rate measurements into logarithmic bins (e.g. $[0\text{--}1\text{ms}, 1\text{--}10\text{ms}, 10\text{--}100\text{ms}]$). Binning eliminates sensitivity to microscopic floating-point jitter.
3. **Packet Size Upper Bound Calibration:**
   Jumbo frame networks require explicit subnet context. An IDS must normalize packet length against the negotiated path MTU to prevent large legitimate packets from blinding the classifier to attack payloads.
4. **Quarantine Rather Than Silent Default (Safe Failure Policy):**
   Always isolate non-finite rates and severely degraded flows (`INVALID_NON_FINITE`, `UNPARSEABLE_ANOMALY`) rather than allowing the imputer to fabricate a normal benign flow.
5. **Hybrid Ensemble Deployment (Supervised + Unsupervised):**
   When supervised models suffer evasion under timing or size changes, unsupervised models (Isolation Forest) monitor geometric density and provide orthogonal detection signals.

---

## 6. Student Interview Defense & Viva Guide

When asked about model robustness and security in a technical interview:

**Q: "Your model achieved 98.9% F1-score on CIC-IDS2017. Is it ready for enterprise deployment?"**
> *"No, claiming production readiness based solely on clean academic benchmark splits is a classic mistake. In Phase 7 of NetSentry AI, we stress-tested our champion LightGBM model under physically defensible perturbations. We discovered that while the model is resilient to 25% missing telemetry (retaining 0.907 F1), it is brittle to continuous measurement noise: adding just 5% NIC clock jitter caused 405 attack flows to flip to benign, dropping Macro-F1 from 0.989 to 0.662. This taught us that orthogonal tree splits create sharp decision boundaries in continuous timing space. A production system must incorporate noise-augmented training and logarithmic feature discretization."*

**Q: "How do you handle corrupted or missing inputs during inference?"**
> *"We implemented an explicit safe failure and quarantine architecture. Normal median imputation is permitted only for mild missingness on finite features (`IMPUTED_VALID`). When a flow contains non-finite values (`+inf`/`-inf` from zero-duration rate calculations) or severe missingness (>80%), silently imputing it would synthesize an artificial normal flow and report attacks as benign. NetSentry AI isolates these records as `QUARANTINE_NON_FINITE` or `UNPARSEABLE_ANOMALY` with prediction `-1`, ensuring sensor failures and corrupted packets trigger human analyst review rather than bypassing detection."*

**Q: "Why did initial robustness tests report 0% change on Jumbo Frames and Line-Rate Bursts?"**
> *"During our Phase 7.1 audit, we discovered that the test harness used generic snake_case column names that did not match the Title Case schema of CIC-IDS2017. As a result, zero features were transformed, which was mistakenly logged as 0% change. Rather than assuming the model was immune, we implemented semantic column matching, input verification, and an 'UNSUPPORTED' fallback. When Jumbo Frames (MTU 9000) were genuinely applied across the 10 packet size features, LightGBM F1 actually dropped from 0.989 to 0.664 (33.3% flip rate) because attack signatures were masked by large segment sizes. This taught us that empirical robustness testing must verify the input actually changed before drawing conclusions."*
