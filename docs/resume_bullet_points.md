# NetSentry AI — Resume Bullet Points & Interview Defense Guide

*Three publication-grade, metrics-driven resume bullet points tailored for Software Engineering, Machine Learning, and Cybersecurity internship/full-time applications. Based exclusively on implemented and verified achievements.*

---

## The 3 Resume Bullet Points

### Bullet Point 1: Machine Learning & High-Throughput Pipeline Engineering
> **Architected an end-to-end, leakage-free Network Intrusion Detection platform benchmarking 11 ML models (LightGBM, XGBoost, Random Forest, MLP, SVM) across authentic CIC-IDS2017 and UNSW-NB15 datasets; achieved 98.9% Macro-F1 with sub-0.015ms inference latency and reduced False Positive Rate to 1.59% via validation-constrained decision threshold calibration.**

### Bullet Point 2: Empirical ML Research & Zero-Day Anomaly Detection
> **Conducted empirical cybersecurity research quantifying domain shift; engineered a semantic 6-feature flow alignment framework proving a 67.2% cross-dataset F1 degradation (CIC $\to$ UNSW) due to covariate shift, and implemented unsupervised Isolation Forest anomaly detection that discovered 66.7% of novel zero-day DoS attacks completely missed by supervised baselines.**

### Bullet Point 3: Network Systems Engineering & Explainable AI (XAI)
> **Engineered a bidirectional 5-tuple PCAP ingestion engine aggregating packet captures into flow telemetry; integrated local z-score feature attribution with automated plain-English SOC incident diagnostics and interactive Streamlit dashboards, enabling real-time telemetry inspection and automated firewall mitigation advice.**

---

## Plain-English Breakdown & Interview Defense

### Defending Bullet Point 1:

#### What each phrase means in simple English:
- **"Leakage-free Network Intrusion Detection platform"**: I built a system where data preprocessing (scaling and missing-value imputation) is strictly isolated inside cross-validation training folds. The test data remains completely untouched until the final evaluation, avoiding the common beginner mistake of "cheating" by letting test statistics leak into the training process.
- **"11 ML models across authentic datasets"**: Rather than testing just one algorithm on toy data, I implemented and compared 11 algorithms across 6 distinct machine learning families (linear, trees, bagging, gradient boosting, neural networks, unsupervised) on authentic UNB and UNSW network captures.
- **"98.9% Macro-F1 with sub-0.015ms inference latency"**: LightGBM achieved a 98.9% Macro-F1 score (equally weighting benign and malicious traffic, not falling for the Accuracy Trap) while scoring each network connection in 0.013 milliseconds—fast enough for high-speed routers.
- **"Validation-constrained decision threshold calibration"**: Rather than blindly using the default 0.50 threshold, I swept probability thresholds on validation folds to enforce a strict False Positive Rate ($< 1.0\%$) to protect SOC security analysts from alert fatigue.

#### Likely Interview Question:
> *"Why did LightGBM outperform traditional Random Forest and Neural Networks in your benchmark?"*
> **Your Answer:** "Tabular network flow features have sharp non-linear decision boundaries (e.g. specific packet length cutoffs or rate spikes). Gradient-boosted histogram trees like LightGBM and XGBoost excel on tabular data because they bin features into discrete histograms and iteratively correct residual errors on hard examples, whereas neural networks struggle without extensive feature scaling and larger datasets, and Random Forest has a much higher memory footprint and inference latency."

---

### Defending Bullet Point 2:

#### What each phrase means in simple English:
- **"Semantic 6-feature flow alignment framework"**: CIC-IDS2017 and UNSW-NB15 have completely different column names and units (e.g. microseconds vs seconds, separate forward/backward packet counts vs total packets). I mapped them to a unified mathematical schema: connection duration, forward packets, backward packets, byte rate, packet rate, and average packet size.
- **"67.2% cross-dataset F1 degradation due to covariate shift"**: When a model trained on Canadian university traffic (CIC-IDS2017) was tested on Australian cyber range traffic (UNSW-NB15), its detection score dropped by 67.2%. This proves that high accuracy in one lab does not guarantee real-world generalization because different networks have different baseline packet rates and MTUs.
- **"Discovered 66.7% of novel zero-day DoS attacks"**: I hid the entire DoS attack category during training. When tested, the supervised model had a 0% recall (it had never seen DoS before and thought it was benign). However, an unsupervised Isolation Forest—which learns normal traffic geometry without labels—flagged 66.7% of the novel DoS attacks as abnormal outliers.

#### Likely Interview Question:
> *"What is the main limitation of relying on unsupervised anomaly detection if it caught 66.7% of zero-day attacks?"*
> **Your Answer:** "The trade-off is a significantly higher False Alarm Rate. While the supervised model had an FPR of 2.1%, the unsupervised Isolation Forest had an FPR of 9.0%. In network security, an anomaly is not always an attack—a legitimate large video upload or database backup is statistically anomalous. Therefore, unsupervised models are best used as an early-warning telemetry feed to prompt human investigation, rather than an automated blocking firewall."

---

### Defending Bullet Point 3:

#### What each phrase means in simple English:
- **"Bidirectional 5-tuple PCAP ingestion engine"**: Raw network captures (.pcap files) are just streams of bytes. I wrote a module using Scapy that groups packets into connection flows by tracking their Source IP, Destination IP, Source Port, Destination Port, and Protocol, calculating forward and backward statistics.
- **"Local z-score feature attribution"**: When the model flags a connection as malicious, it calculates how many standard deviations ($z$-score) each feature is from normal traffic medians (e.g., *SYN flag count is +4.8 standard deviations above normal*).
- **"Automated plain-English SOC incident diagnostics"**: I built a narrative engine that converts these mathematical deviations into human-readable sentences for junior security analysts, recommending specific firewall actions (like blacklisting an IP or throttling a port).

#### Likely Interview Question:
> *"How does your PCAP reader handle directionality when grouping packets into a 5-tuple?"*
> **Your Answer:** "I used a canonical key: ordering the two endpoints lexicographically $(\min(\text{IP}_A, \text{IP}_B), \max(\text{IP}_A, \text{IP}_B))$. I then determine the forward direction by identifying the client that transmitted the initial TCP SYN packet or the first observed UDP datagram, allowing accurate forward-versus-backward packet and byte rate calculations."
