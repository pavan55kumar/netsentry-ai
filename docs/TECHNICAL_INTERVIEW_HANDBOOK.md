# NetSentry AI — Technical Interview Handbook

**Target Audience:** Technical Interviewers, Engineering Hiring Managers, and Students preparing for Software Engineering, Machine Learning Engineering, or Security Engineering interviews.  
**Author Persona:** 3rd-Year B.Tech Information Science & Engineering Student, NMAM Institute of Technology, Nitte.  

---

# SECTION A: Project Explanation & Walkthrough

### Q1. "Can you give a 30-second elevator pitch of your project?"
- **Simple Answer:**  
  "NetSentry AI is a machine-learning network intrusion detection research platform. Because over 85% of modern traffic is encrypted with TLS/HTTPS, deep packet inspection of payload bytes is no longer feasible. NetSentry AI analyzes bidirectional network connection flows—using metadata like packet rates, durations, and TCP flags—to detect intrusions without decrypting payloads, stress-tests how models break under real-world timing jitter, and enforces strict data isolation."
- **Deep Technical Explanation:**  
  "The project bridges Data Communication & Networking (DCN) with production ML engineering. It takes raw offline PCAP packet captures, aggregates packets into bidirectional 5-tuple flows using a 120-second idle session timeout, and evaluates 11 supervised and unsupervised algorithms across CIC-IDS2017 and UNSW-NB15 datasets. Our champion LightGBM model achieves a 0.9892 holdout Macro-F1 at 0.016 ms/flow latency. Crucially, the platform investigates why academic models fail in production: uncovering a 66.8% cross-dataset transfer collapse due to concept inversion in flow duration, and showing that 5% clock jitter collapses tree F1 from 0.989 to 0.662."
- **Likely Follow-Up Question:**  
  "Why did you choose to evaluate flow metadata instead of inspecting payload bytes?"
- **Common Incorrect Answer to Avoid:**  
  "I didn't inspect payloads because payloads are too hard to parse." *(Incorrect: Payloads are actively encrypted with TLS 1.3 / AES-GCM; inspecting payloads requires breaking end-to-end encryption or running expensive man-in-the-middle proxies).*

---

### Q2. "Can you give a 90-second technical explanation of your architecture?"
- **Simple Answer:**  
  "The platform has five stages: First, offline packet ingestion aggregates raw PCAP packets into bidirectional flows. Second, our preprocessing pipeline detects target leakage and prunes duplicates. Third, scikit-learn pipelines encapsulate imputation, scaling, and models to ensure training isolation. Fourth, an inference safety engine quarantines non-finite values (+Inf/-Inf) rather than letting them pass as benign. Finally, an 8-view Streamlit dashboard provides local explainability and privacy-preserving CSV exports."
- **Deep Technical Explanation:**  
  "1. **Ingestion & Aggregation:** In `src/netsentry/pcap/flow_extractor.py`, streaming Scapy `PcapReader` groups packets using an ordered 5-tuple key: `(src_ip, sport, dst_ip, dport, proto)`. Flows are bounded by a 120-second idle timeout, calculating forward/backward packet counts, byte rates, duration, and TCP flags.  
  2. **Zero-Leakage Preprocessing:** In `src/netsentry/data/preprocessor.py`, `detect_target_leakage()` strips ground-truth labels and session identifiers. In `models/factory.py`, `SimpleImputer` and `StandardScaler` reside inside `sklearn.pipeline.Pipeline`, guaranteeing that statistics are computed exclusively on `X_train`.  
  3. **Multi-Paradigm Inference:** Evaluates gradient-boosted trees (LightGBM, XGBoost), random forests, linear models, and unsupervised Isolation Forest.  
  4. **Safe Failure:** In `predict.py`, division-by-zero rates (`+Inf`) or $>80\%$ missing features are assigned `prediction = -1` (`QUARANTINE_NON_FINITE`), preventing corrupt traffic from masquerading as benign.  
  5. **Explainability & Privacy:** Computes local $z$-score deviations against normal baseline medians to generate plain-English SOC alerts, while masking IP host octets (`192.168.1.***`)."
- **Likely Follow-Up Question:**  
  "How did you prevent data leakage during feature scaling and threshold tuning?"
- **Common Incorrect Answer to Avoid:**  
  "I scaled the dataset with `StandardScaler.fit_transform(df)` before splitting." *(Incorrect: This leaks the test set mean and variance into training).*

---

### Q3. "Walk me through your project in detail: problem, motivation, model choice, results, limitations, and future research." (5-Minute Walkthrough)
- **Problem & Motivation:**  
  "Most published NIDS papers claim $>99\%$ accuracy on academic benchmarks like CIC-IDS2017. However, when deployed on live networks, these models suffer from the **Base-Rate Fallacy** (generating 94%+ false alarms in low-prevalence environments), fail completely under domain shift, and break when encountering sensor clock jitter. I wanted to build a platform that doesn't just chase high accuracy, but rigorously stress-tests where ML models break and enforces production-grade safety."
- **Architecture & Implementation:**  
  "I implemented a 63-test modular Python architecture. I wrote an offline PCAP flow extractor that reconstructs bidirectional sessions, built a model factory constructing zero-leakage scikit-learn pipelines across 11 algorithms, and created a validation-based decision threshold optimizer."
- **Model Choice & Results:**  
  "We selected **LightGBM** as the champion over Random Forest. While both achieve high Macro-F1 (0.9892 vs 0.9767), LightGBM executes inference in **0.0156 ms/flow** (12x faster than Random Forest's 0.188 ms) with a **344 KB footprint** (77% smaller than RF's 1.5 MB). Decision Tree was the fastest at 0.005 ms/flow, making it suitable for line-rate edge filtering."
- **Key Scientific Findings:**  
  "1. **Cross-Dataset Generalization:** Transferring from CIC-IDS2017 to UNSW-NB15 caused F1 to collapse from 0.9488 to 0.3148. Feature ablation proved this was due to **concept inversion** in flow duration: DoS attacks in CIC-IDS are long-lived sessions, while exploits in UNSW are microsecond bursts. Training on mixed domains restored F1 to 0.8932.  
  2. **Measurement Jitter:** Adding $\pm 5\%$ Gaussian noise to timing features dropped LightGBM F1 to 0.6617 (flipping 405 attacks to benign) because orthogonal tree splits partition tight automated attack intervals.  
  3. **Zero-Day Discovery:** Supervised models missed 100% of withheld attack families, while Isolation Forest detected 66.8% of novel DoS attacks without labels, but suffered an 8.4% false positive rate."
- **Limitations & Future Work:**  
  "NetSentry AI operates on L3/L4 metadata, making it blind to malicious encrypted payloads that mimic normal volumetric profiles. In the future, I plan to integrate an eBPF in-kernel collector for wire-speed packet capture and implement noise-augmented training to harden tree split boundaries."

---

# SECTION B: Machine Learning Engineering

### Q4. "What is the difference between supervised classification and unsupervised anomaly detection in network security?"
- **General Theory:**  
  Supervised classification learns decision boundaries from labeled training data containing known attack categories and benign traffic. Unsupervised anomaly detection fits a model solely on the structural or geometric density of normal traffic, flagging any observation that deviates from the baseline as an anomaly.
- **Project-Specific Fact:**  
  In NetSentry AI, our supervised LightGBM model achieved 0.9892 Macro-F1 on known attacks, but exhibited **0.0% recall** when an attack family (like DoS) was withheld from training data. Conversely, **Isolation Forest** successfully detected **66.79% of novel DoS floods** without prior labels by isolating sparse volumetric bursts, but incurred an **8.4% false alarm rate** on normal traffic and completely missed stealthy low-packet probes (`PortScan` recall: 0.0%).
- **Likely Follow-Up Question:**  
  "Why did Isolation Forest miss PortScan while detecting DoS?"
- **Common Incorrect Answer to Avoid:**  
  "Isolation Forest can detect all zero-day attacks because it doesn't need labels." *(Incorrect: It only detects volumetric or statistical outliers; stealthy attacks geometrically blend into normal traffic).*

---

### Q5. "Why did you choose LightGBM over Random Forest as your champion model?"
- **General Theory:**  
  Both are decision tree ensembles. Random Forest builds independent trees using bagging and majority voting. LightGBM builds sequential trees using gradient boosting with histogram-based feature binning and leaf-wise (best-first) tree growth.
- **Project-Specific Fact:**  
  In our empirical benchmark (`artifacts/phase6_experiment_results.json`):
  1. **Detection Performance:** LightGBM achieved higher Macro-F1 (**0.9892 vs 0.9767**) and a lower False Positive Rate (**1.59% vs 2.59%**).
  2. **Inference Latency:** LightGBM scored flows in **0.0156 ms/flow**, whereas Random Forest required **0.1881 ms/flow** (LightGBM is **12x faster**).
  3. **Memory Footprint:** LightGBM's serialized disk footprint is **344 KB**, compared to **1,508 KB** for Random Forest (Random Forest consumes 4.4x more RAM).
- **Likely Follow-Up Question:**  
  "Why is LightGBM so much faster during inference than Random Forest?"
- **Common Incorrect Answer to Avoid:**  
  "LightGBM is faster because it uses fewer trees." *(Incorrect: LightGBM uses 300 boosted trees with shallow depth, but evaluates histogram bins and leaf-wise nodes rather than 500 fully-grown parallel trees).*

---

### Q6. "Why is accuracy a deceptive metric in network intrusion detection? What metrics should be used?"
- **General Theory:**  
  The **Accuracy Trap** occurs under severe class imbalance. If a dataset contains 99% benign flows and 1% attacks, a naive Zero-R dummy model that predicts 'benign' for every flow achieves 99% accuracy while having 0.0% attack recall and 0.0 Macro-F1.
- **Project-Specific Fact:**  
  In `artifacts/metrics.json`, our Zero-R baseline achieved 71.3% accuracy on an imbalanced split while having an attack recall of 0.0. To avoid this, NetSentry AI optimizes for:
  - **Macro-Averaged F1-Score:** Treats all classes equally regardless of frequency ($\frac{1}{C}\sum F1_c$).
  - **False Positive Rate (FPR):** $\frac{\text{FP}}{\text{FP} + \text{TN}}$, measuring false alarms on benign traffic.
  - **Malicious Recall (TPR):** $\frac{\text{TP}}{\text{TP} + \text{FN}}$, measuring the proportion of caught intrusions.
- **Likely Follow-Up Question:**  
  "How does attack prevalence affect real-world precision?"
- **Common Incorrect Answer to Avoid:**  
  "High accuracy means the model is ready for deployment." *(Incorrect: High accuracy with a 1.5% FPR generates 137 million false alarms daily on a 10 Gbps link).*

---

### Q7. "What is data leakage and how did you prevent it in your codebase?"
- **General Theory:**  
  Data leakage occurs when information from outside the training partition (such as test set distributions, ground truth labels, or future timestamps) contaminates the training process.
- **Project-Specific Fact:**  
  We enforced three explicit architectural guardrails:
  1. **Pipeline Encapsulation:** In `models/factory.py`, `SimpleImputer` and `StandardScaler` are wrapped inside `sklearn.pipeline.Pipeline`. Preprocessors call `fit_transform` only on `X_train` during cross-validation folds.
  2. **Automated Keyword Stripping:** In `data/preprocessor.py`, `detect_target_leakage()` automatically identifies and removes columns containing target indicators (`label`, `attack_category`) and direct session identifiers (`src_ip`, `dst_ip`, `timestamp`, `flow_id`).
  3. **Exact Row Deduplication:** In `preprocessor.py`, exact duplicate feature rows are pruned using `drop_duplicates(subset=numeric_cols)` prior to holdout splitting, preventing duplicate flow records from leaking across partitions.
- **Likely Follow-Up Question:**  
  "How did you select decision thresholds without leaking test set performance?"
- **Common Incorrect Answer to Avoid:**  
  "I tuned the threshold on the test set to maximize test F1." *(Incorrect: That directly overfits the decision threshold to the evaluation holdout).*

---

### Q8. "How does validation-based threshold optimization work?"
- **General Theory:**  
  The standard 0.50 probability threshold assumes equal costs for false positives and false negatives. In network security, false positives cause analyst fatigue, while false negatives cause breaches. Threshold optimization calibrates $\tau$ on validation data to meet an operational constraint.
- **Project-Specific Fact:**  
  In `src/netsentry/training/threshold.py`, `optimize_decision_threshold()` takes a fitted model and a validation partition (`X_val`, `y_val`). It sweeps 91 candidate thresholds ($\tau \in [0.05, 0.95]$), computes the confusion matrix, and selects $\tau$ that maximizes F1 subject to a strict FPR limit (e.g. $\text{FPR} \le 5\%$). In `generalization_strategies.py`, this tuned $\tau$ is then evaluated out-of-fold on untouched test holdouts.
- **Likely Follow-Up Question:**  
  "What happens if an algorithm does not support `predict_proba`?"
- **Common Incorrect Answer to Avoid:**  
  "All machine learning models natively output calibrated probabilities." *(Incorrect: Hard margin SVMs and Decision Trees do not output calibrated probabilities; LinearSVC requires Platt calibration via `CalibratedClassifierCV`).*

---

# SECTION C: Data Communication and Networking (DCN)

### Q9. "Explain the difference between packet-level analysis and flow-level analysis."
- **General Theory:**  
  Packet analysis inspects individual Layer 2/3/4 packets and their Layer 7 application payloads (Deep Packet Inspection). Flow analysis aggregates all packets sharing a bidirectional communication session into a single summary statistical record.
- **Project-Specific Fact:**  
  NetSentry AI operates on **bidirectional flow telemetry**. Packet inspection of 100 Gbps traffic requires terabytes of RAM and fails when traffic is encrypted with TLS 1.3. Flow analysis summarizes millions of packets into compact feature vectors (duration, packet counts, inter-arrival times, byte rates, TCP flags), enabling machine learning classification at wire-speed without payload decryption.
- **Likely Follow-Up Question:**  
  "What is the canonical 5-tuple used to define a flow?"
- **Common Incorrect Answer to Avoid:**  
  "A flow is just a single packet with extra metadata." *(Incorrect: A flow is an aggregated conversation representing tens, hundreds, or thousands of packets over time).*

---

### Q10. "What is the canonical 5-tuple and how do you handle bidirectional flows?"
- **General Theory:**  
  The 5-tuple consists of: Source IP, Destination IP, Source Port, Destination Port, and Layer 4 Transport Protocol (TCP/UDP/ICMP).
- **Project-Specific Fact:**  
  In `src/netsentry/pcap/flow_extractor.py`, client-to-server and server-to-client packets have inverted source and destination sockets. To aggregate them into a single bidirectional flow, we normalize the flow key:
  ```python
  if (src_ip, sport) <= (dst_ip, dport):
      flow_key = (src_ip, sport, dst_ip, dport, proto)
      is_fwd = True
  else:
      flow_key = (dst_ip, dport, src_ip, sport, proto)
      is_fwd = False
  ```
  Packets matching `is_fwd` increment `total_fwd_packets` and `fwd_bytes`, while inverted packets increment `total_backward_packets` and `bwd_bytes`.
- **Likely Follow-Up Question:**  
  "How do you determine when a flow has ended?"
- **Common Incorrect Answer to Avoid:**  
  "Flows end only when an explicit TCP FIN or RST packet is sent." *(Incorrect: Many sessions drop silently or use UDP, which has no connection teardown; flow collectors must enforce idle and active timeout thresholds).*

---

### Q11. "How do flow timeouts work (idle timeout vs active timeout)?"
- **General Theory:**  
  An **idle timeout** closes a flow if no packets are observed for a specified duration (e.g. 120 seconds). An **active timeout** terminates a continuous long-lived flow (e.g. after 30 minutes) to export telemetry periodically and prevent buffer exhaustion.
- **Project-Specific Fact:**  
  In `src/netsentry/pcap/flow_extractor.py`, we enforce `idle_timeout_sec = 120.0`. During packet iteration, if `pkt_time - active_flow["end_time"] > 120.0`, the existing flow record is finalized and saved to `completed_flows`, and a new flow record is initiated for subsequent packets.
- **Likely Follow-Up Question:**  
  "What happens if packet capture clocks roll backwards or drift?"
- **Common Incorrect Answer to Avoid:**  
  "Packet timestamps in PCAP files are always perfectly sequential." *(Incorrect: Multi-core NIC capture cards often buffer packets across queues, causing out-of-order timestamps).*

---

### Q12. "Why can't metadata-based intrusion detection inspect encrypted payloads, and how do attacks manifest in flow features?"
- **General Theory:**  
  TLS 1.3 and modern cipher suites (AES-GCM, ChaCha20-Poly1305) encrypt application-layer payloads end-to-end. Flow-level intrusion detection operates strictly on L3/L4 headers.
- **Project-Specific Fact:**  
  Even when payload bytes are encrypted, attack behaviors induce distinct physical flow geometries:
  - **SYN Flood (DDoS):** Extremely high `total_fwd_packets`, `syn_flag_count > 0`, and `total_backward_packets == 0` (the target is overwhelmed and cannot send SYN-ACKs).
  - **Port Scan:** High `flow_packets_per_second` with duration near 0 ms, targeting multiple destination ports with single SYN packets.
  - **Data Exfiltration:** High forward byte rate with asymmetric forward-to-backward byte ratios.
- **Likely Follow-Up Question:**  
  "What attacks are invisible to flow metadata?"
- **Common Incorrect Answer to Avoid:**  
  "Flow metadata can detect all attacks including SQL injections." *(Incorrect: A single SQL injection string sent inside an established HTTPS session has the exact same flow geometry as a legitimate form submission).*

---

# SECTION D: Software Engineering & Operational Safety

### Q13. "How did you structure your inference pipeline for safe failure on corrupted or non-finite inputs?"
- **General Theory:**  
  In production, sensors occasionally divide by zero (0-duration flows producing `+Inf` rates) or drop telemetry (>80% missing features). A naive system that imputes medians will classify non-finite corrupted rows as normal benign traffic, creating a severe security vulnerability.
- **Project-Specific Fact:**  
  In `src/netsentry/predict.py`, `score_flows()` enforces a strict **Safe Failure Quarantine Policy**:
  ```python
  is_non_finite = np.isinf(X_raw).any(axis=1)
  if is_non_finite.any() and quarantine_non_finite:
      result.loc[is_non_finite, "prediction"] = -1
      result.loc[is_non_finite, "risk_level"] = "QUARANTINE_NON_FINITE"
  ```
  Rows with `+Inf`/`-Inf` or $>80\%$ NaNs are quarantined with prediction `-1` rather than silently imputed to benign medians. Quarantined flows are displayed with specialized alert badges in the Streamlit dashboard.
- **Likely Follow-Up Question:**  
  "How do you distinguish mild missingness from severe corruption?"
- **Common Incorrect Answer to Avoid:**  
  "I used `df.dropna()` to throw away bad rows." *(Incorrect: Dropping rows silently discards evidence of sensor failures or adversarial DoS attacks on the monitoring engine).*

---

### Q14. "How do you protect user privacy and prevent sensitive data leakage in logs?"
- **General Theory:**  
  Operational logs must provide diagnostic forensic value without exposing Personally Identifiable Information (PII), credentials, or internal network topology.
- **Project-Specific Fact:**  
  In `src/netsentry/utils/logging.py`, we implemented:
  1. **IP Privacy Masking:** `redact_ip_address()` replaces IPv4 host octets (`192.168.1.45` $\to$ `192.168.1.***`) and IPv6 host endpoints (`2001:db8:85a3::7334` $\to$ `2001:db8:85a3:****`), preserving subnet routing context while anonymizing endpoints.
  2. **Secret Scrubbing:** `sanitize_log_message()` uses regex to redact passwords, bearer tokens, AWS access keys (`AKIA...`), and student Windows user profile directories (`C:\Users\username\...` $\to$ `[USER_DIR]/...`).
- **Likely Follow-Up Question:**  
  "Why mask only the host octet instead of the entire IP address?"
- **Common Incorrect Answer to Avoid:**  
  "We don't need to mask IPs because IP addresses are public." *(Incorrect: Internal IP addresses reveal subnet topologies and are classified as personal data under GDPR/privacy regulations).*

---

### Q15. "How do you measure operational performance, and what is the difference between batch throughput and per-flow latency?"
- **General Theory:**  
  **Batch Throughput** measures how many flow records the engine can score per second in bulk (flows/sec), amortizing vectorized SIMD operations. **Per-Flow Latency** measures the end-to-end elapsed time required to score an individual arriving flow (milliseconds/flow).
- **Project-Specific Fact:**  
  In our empirical benchmark (`artifacts/phase8_performance_results.json`):
  - **Batch Throughput:** **15,240 flows/second** on a standard 4-core laptop.
  - **Per-Flow Latency:** **0.0156 ms/flow** for LightGBM, and **0.0049 ms/flow** for Decision Tree.
  - While batch processing achieves 15K+ flows/sec, streaming single-packet ingestion incurs Python Scapy interpreter overhead (~10,000 packets/sec).
- **Likely Follow-Up Question:**  
  "What is the bottleneck for scaling to 100 Gbps line rate?"
- **Common Incorrect Answer to Avoid:**  
  "Python can easily handle 100 Gbps traffic." *(Incorrect: 100 Gbps carries ~148 million packets/sec; Python interpreter and GIL overhead restrict it to offline forensics. Line-rate capture requires C++/DPDK or eBPF).*

---

# SECTION E: Research Defense & Failure Analysis

### Q16. "Why did 5% measurement jitter cause your champion LightGBM model's F1-score to collapse from 0.989 to 0.662?"
- **General Theory:**  
  Decision trees partition continuous feature space using orthogonal, axis-aligned hyperplanes (step functions). When training data contains tightly clustered automated attack intervals, trees place split thresholds immediately adjacent to those clusters.
- **Project-Specific Fact:**  
  In `artifacts/phase7_robustness_results.json`, adding $\pm 5\%$ zero-mean Gaussian noise to timing features (`Flow Duration`, `Flow IAT Mean`, `Packet Rates`) collapsed LightGBM Macro-F1 from **0.9892 to 0.6617**, flipping **33.12% of test predictions** and causing **405 malicious attack flows to flip to benign**. Because automated tools like LOIC generate deterministic packet arrival intervals, tree splits were placed tightly around those intervals. Small physical clock drift or network packet delay variation (PDV) pushed flows across the hyperplane into the benign region.
- **Likely Follow-Up Question:**  
  "How can you make the model robust against measurement jitter?"
- **Common Incorrect Answer to Avoid:**  
  "By training for more epochs or adding more trees." *(Incorrect: More trees simply create sharper, more brittle step-function boundaries; the solution is noise-augmented training and logarithmic feature discretization).*

---

### Q17. "What is Concept Inversion, and why did your model collapse when tested across datasets?"
- **General Theory:**  
  Concept Inversion occurs when a feature has an opposite statistical relationship with the target variable between the source and target domains.
- **Project-Specific Fact:**  
  When transferring a model trained on CIC-IDS2017 to UNSW-NB15, Macro-F1 collapsed from **0.9488 to 0.3148** (a 66.82% degradation). Using feature ablation in `src/netsentry/research/generalization_strategies.py`, we identified **flow duration** as the inverted feature:
  - In **CIC-IDS2017**, attack traffic consists of long-lived DoS flood sessions (high duration), while benign traffic consists of brief web requests (low duration).
  - In **UNSW-NB15**, attack traffic consists of microsecond exploit probes (low duration), while benign traffic includes multi-minute file transfers (high duration).
  The tree learned: `if duration > threshold -> Attack`. On UNSW-NB15, this rule classified attacks as benign and benign transfers as attacks!
- **Likely Follow-Up Question:**  
  "How did you solve concept inversion?"
- **Common Incorrect Answer to Avoid:**  
  "I normalized the features using StandardScaler." *(Incorrect: Linear scaling cannot fix an inverted correlation; we resolved it by training on joint multi-domain partitions, forcing the model to learn duration-invariant features like TCP flag ratios).*

---

### Q18. "Why is your 8-feature PCAP demonstration not equivalent to evaluating the full CIC-IDS2017 dataset?"
- **General Theory:**  
  Academic datasets are generated by specialized offline feature extraction tools (like CICFlowMeter) that compute dozens of complex internal state variables over long packet captures.
- **Project-Specific Fact:**  
  CIC-IDS2017 contains **77 statistical features**, including forward/backward subflow bytes, inter-arrival time standard deviations, active/idle timeout counts, and TCP initial window sizes. Our offline PCAP parser extracts the **8-feature canonical schema** (`duration`, `fwd_pkts`, `bwd_pkts`, `byte_rate`, `packet_rate`, `syn_flags`, `rst_flags`, `avg_size`). While our demo model (`best_model.joblib`) is trained to score these 8 features out-of-the-box, it is an **educational functional demonstration of packet ingestion**, *not* a full-scale 77-feature DPI evaluation.
- **Likely Follow-Up Question:**  
  "What would be required to extract all 77 features from live PCAP?"
- **Common Incorrect Answer to Avoid:**  
  "The 8 features are identical to the 77 features because they use the same names." *(Incorrect: The 77 features require complex state machines tracking subflow buffers and microsecond TCP window flags).*
