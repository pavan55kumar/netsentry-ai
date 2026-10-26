# NetSentry AI — Scientific Evaluation Guide

## 1. Why Accuracy Fails in Cybersecurity (The Accuracy Trap)

In conventional computer vision or natural language processing, classes are frequently balanced (e.g., 50% dogs, 50% cats).
In production network intrusion detection, datasets are **massively imbalanced**:
- 98.5% of network flows are legitimate user traffic (Benign).
- 1.5% of network flows are malicious scans, brute-force attempts, or malware beacons.

### The Mathematical Trap:
Suppose an evaluation dataset contains 10,000 flows:
$$\text{Benign} = 9,850 \quad | \quad \text{Malicious} = 150$$

A naive "Zero-R" dummy model that always outputs `BENIGN` scores:
$$\text{Accuracy} = \frac{9,850 + 0}{10,000} = 98.5\%$$

Despite boasting **98.5% accuracy**, this system detected **zero attacks** ($\text{Recall} = 0\%$) and permitted 100% of intrusions past the firewall.
**NetSentry AI automatically compares every model against a majority dummy classifier to expose this trap.**

---

## 2. Core Scientific Metrics

### A. Precision (Malicious / Positive Class)
$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
- **Operational Meaning:** Of all alarms triggered by the model, what fraction were genuine attacks?
- **Security Consequence:** Low precision causes **Alert Fatigue**; human analysts are swamped by thousands of false alarms and begin ignoring notifications.

### B. Recall (Sensitivity / Detection Rate)
$$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
- **Operational Meaning:** Of all actual cyber attacks traversing the wire, what fraction did the model detect?
- **Security Consequence:** Low recall represents **Breach Risk**; stealthy attacks enter the corporate network undetected.

### C. Macro-F1 Score (NetSentry Primary Selection Metric)
$$\text{Macro-F1} = \frac{\text{F1}_{\text{benign}} + \text{F1}_{\text{malicious}}}{2}$$
- **Operational Meaning:** Evaluates performance giving **equal weight** to rare cyber attacks and massive benign volumes. A model with 0% attack recall cannot achieve a Macro-F1 higher than ~0.50 regardless of how many benign flows it correctly identifies.

### D. False Positive Rate (FPR)
$$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$
- **Operational Meaning:** What fraction of normal network operations were wrongly flagged? In enterprise networks processing millions of flows/sec, an FPR of even 1.0% generates tens of thousands of false alarms daily.

### E. PR-AUC vs. ROC-AUC
- **ROC-AUC** plots $\text{TPR}$ vs $\text{FPR}$. When the negative (benign) class is massive, $\text{TN}$ dominates the denominator of $\text{FPR}$, making ROC curves look deceptively close to 1.0.
- **PR-AUC (Precision-Recall AUC)** plots $\text{Precision}$ vs $\text{Recall}$. Because it excludes $\text{TN}$, PR-AUC is mathematically sensitive to false alarms on the minority class and is the gold standard for network intrusion evaluation.

---

## 3. Decision Threshold Calibration

By default, binary classifiers apply a decision threshold of $\tau = 0.50$:
$$\hat{y} = \begin{cases} 1 & \text{if } P(y=1|X) \ge 0.50 \\ 0 & \text{otherwise} \end{cases}$$

NetSentry AI's **Evaluation Center** allows operators to sweep $\tau \in [0.05, 0.95]$:
- **Low Threshold ($\tau = 0.20$):** High-sensitivity / High-security mode. Maximizes attack recall, but incurs higher false alarms.
- **High Threshold ($\tau = 0.80$):** Conservative firewall mode. Alerts strictly on high-confidence attack indicators, reducing false alarms to near zero.
