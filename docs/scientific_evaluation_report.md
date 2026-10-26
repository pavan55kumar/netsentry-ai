# NetSentry AI — Scientific Evaluation, Alert Fatigue & Metrics Report

## 1. Executive Summary

Evaluation in Network Intrusion Detection Systems (NIDS) presents unique statistical challenges that differentiate it from standard machine learning domains:
1. **Extreme Class Imbalance**: Malicious traffic constitutes $< 1\%$ to $5\%$ of total packets on healthy enterprise networks.
2. **Asymmetric Operational Costs**: A false alarm costs 15 minutes of an analyst's triage time; a missed intrusion (false negative) can lead to catastrophic data exfiltration or ransomware encryption.
3. **High-Throughput Alert Fatigue**: On a 10 Gbps core link processing 100,000 flows/sec, an algorithm with an apparently stellar $99.0\%$ specificity ($1.0\%$ FPR) generates **1,000 false alarms every second**, completely overwhelming any Security Operations Center (SOC).

This document establishes the scientific evaluation framework implemented in NetSentry AI to overcome the **Accuracy Trap** and ensure dependable operational performance.

---

## 2. Mathematical Definition of Metrics

Let the confusion matrix elements for binary classification (0 = Benign, 1 = Malicious) be denoted by:
- $TP$: True Positives (Malicious flows correctly blocked)
- $TN$: True Negatives (Benign flows correctly permitted)
- $FP$: False Positives (Benign flows falsely alerted — *False Alarm*)
- $FN$: False Negatives (Malicious flows missed — *Breach*)

### 2.1. Basic Classification Metrics
$$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$
$$\text{Precision} = \frac{TP}{TP + FP}$$
$$\text{Recall (TPR, Detection Rate)} = \frac{TP}{TP + FN}$$
$$\text{False Positive Rate (FPR, Fall-out)} = \frac{FP}{FP + TN} = 1 - \text{Specificity}$$
$$\text{False Negative Rate (FNR, Miss Rate)} = \frac{FN}{TP + FN} = 1 - \text{Recall}$$

### 2.2. Macro-F1 vs Weighted-F1: The Accuracy Trap Exposed
In multi-class or class-imbalanced intrusion datasets, $F_1$ can be averaged in three distinct ways:

$$\text{Macro-}F_1 = \frac{1}{K} \sum_{k=1}^K F_1^{(k)}$$
$$\text{Weighted-}F_1 = \sum_{k=1}^K \frac{N_k}{N} F_1^{(k)}$$

#### Why Weighted-F1 Hides System Failures:
Consider a dataset of 9,800 Benign flows, 150 PortScan flows, and 50 Infiltration flows:
- If a model completely fails to detect Infiltration ($F_1^{(\text{Infiltration})} = 0.0$) and misses half of PortScans ($F_1^{(\text{PortScan})} = 0.5$), but predicts Benign with $99\%$ accuracy:
  - $\text{Weighted-}F_1 \approx 0.985$ (misleadingly suggests near-perfection).
  - $\text{Macro-}F_1 = \frac{0.99 + 0.50 + 0.00}{3} = 0.497$ (**accurately reveals catastrophic failure on minority attacks**).

**NetSentry AI standard: Model selection and cross-validation champion selection strictly use Macro-$F_1$.**

---

## 3. Operational SOC Telemetry & Alert Fatigue Analysis

### The Base-Rate Fallacy in Network Security
By Bayes' Theorem, the probability that an alert actually represents a true attack ($P(\text{Attack} \mid \text{Alert})$) depends critically on the prior probability (base rate) of attacks $P(A)$:

$$P(A \mid \text{Alert}) = \frac{P(\text{Alert} \mid A) \cdot P(A)}{P(\text{Alert} \mid A) \cdot P(A) + P(\text{Alert} \mid \neg A) \cdot P(\neg A)}$$
$$P(A \mid \text{Alert}) = \frac{\text{Recall} \cdot P(A)}{\text{Recall} \cdot P(A) + \text{FPR} \cdot (1 - P(A))}$$

**Numerical Example:**
- Assume base rate $P(A) = 0.001$ ($0.1\%$ of flows are malicious).
- Model Recall = $99.0\%$ ($0.99$).
- Model False Positive Rate = $1.0\%$ ($0.01$).

$$P(A \mid \text{Alert}) = \frac{0.99 \times 0.001}{(0.99 \times 0.001) + (0.01 \times 0.999)} = \frac{0.00099}{0.00099 + 0.00999} = \frac{0.00099}{0.01098} \approx 9.02\%$$

**Takeaway:** Despite a $99\%$ detection rate and a tiny $1\%$ false alarm rate, **over $90\%$ of alerts displayed to analysts are false alarms!** This mathematical reality drives SOC alert fatigue.

---

## 4. Decision Threshold Optimization Engine

Rather than forcing a default decision boundary of $\tau = 0.50$, NetSentry AI implements an automated validation-based threshold calibrator (`netsentry.training.threshold`):

1. **Validation Sweep**: Generates predicted probabilities $P(y=1 \mid \mathbf{x})$ on a held-out validation fold across $\tau \in [0.05, 0.95]$.
2. **Constraint Enforcement**:
   - Finds $\tau^* = \arg\max_{\tau} F_1(\tau)$ subject to $\text{FPR}(\tau) \le \text{Target FPR}_{\max}$ (e.g. $\le 1.0\%$).
3. **Operational Output**:
   - High-sensitivity posture ($\tau \approx 0.20$): Applied during declared red-team exercises or high-threat periods.
   - Low-fatigue posture ($\tau \approx 0.65 - 0.80$): Applied during standard operations to ensure every raised alert represents high-confidence malicious telemetry.

---

## 5. Latency & Resource Footprint Profiling

Network intrusion detection systems operate under real-time line-rate constraints:
- **Wire Speed**: At 10 Gbps with 1,500-byte MTU, up to 833,000 packets/sec traverse the interface.
- **Batch Flow Amortization**: Aggregating packets into 5-tuple flows reduces the evaluation frequency to approximately 10,000–50,000 flows/sec.
- **Latency Budget**: To avoid packet buffering overflows, per-flow scoring latency must remain below $1.0\text{ ms}$.

NetSentry AI continuously profiles two deployment metrics for every candidate model:
1. **Inference Latency ($\text{ms/flow}$)**: Evaluated over batches of 1,000 holdout flows.
2. **Serialized Footprint ($\text{KB}$)**: Serialized size on disk via `joblib`, verifying feasibility for deployment in memory-constrained IoT gateways and edge firewalls.
