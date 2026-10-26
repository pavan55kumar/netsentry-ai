# NetSentry AI — Five-Minute Technical Interview & Viva Demo Runbook

**Candidate Role:** 3rd-Year B.Tech Information Science & Engineering Student  
**Project Title:** NetSentry AI — Advanced ML-Based Network Intrusion Detection & Research Platform  
**Target Audience:** Technical Interviewers, Security Engineering Leads, Academic Viva Examiners  
**Target Duration:** Exactly 5 to 7 Minutes  
**Demonstration URL:** `http://localhost:8501`  

---

## 1. Demo Objectives & Elevator Pitch

### The 30-Second Elevator Pitch
> *"Hello! My name is a 3rd-year Information Science and Engineering student at NMAM Institute of Technology, Nitte, and this is **NetSentry AI**, an ML-based network intrusion detection research platform. Most academic papers claim 99% accuracy on clean benchmark splits like CIC-IDS2017. However, in live deployments, these models experience catastrophic failure under hardware clock jitter, non-finite sensor rates, and domain shift. NetSentry AI bridges Data Communication & Networking (DCN) with Machine Learning: it ingests offline PCAP captures, aggregates them into 5-tuple flows, benchmarks 11 ML algorithms without data leakage, explains alerts with plain-English security narratives, and enforces a strict Safe Failure Quarantine Policy against invalid or adversarial inputs."*

---

## 2. Pre-Demo Checklist (60 Seconds Before Interview)

Before sharing your screen, verify the local environment:

1. **Terminal 1 (Test Suite Smoke Check):**
   ```powershell
   .\.venv\Scripts\python.exe -m unittest discover -s tests -v
   ```
   *Verify: `Ran 63 tests ... OK` (100% passing in ~15.6s).*
2. **Terminal 2 (Launch Web Interface):**
   ```powershell
   .\.venv\Scripts\python.exe -m streamlit run app/main.py
   ```
   *Verify: Browser opens to `http://localhost:8501` displaying the dark-navy cyber dashboard.*
3. **Browser Zoom:** Set browser zoom to 90% or 100% so KPI cards and sidebar navigation are cleanly visible on screen share.
4. **Pre-load Tabs:** Open `Overview` in one tab and have `Traffic Analyzer` and `Research Workbench` ready.

---

## 3. Five-Minute Minute-by-Minute Walkthrough

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                           5-MINUTE DEMO TIMELINE                               │
├─────────────┬─────────────┬─────────────┬─────────────┬────────────────────────┤
│  MINUTE 1   │  MINUTE 2   │  MINUTE 3   │  MINUTE 4   │       MINUTE 5         │
│ Operations  │  Dataset    │   Traffic   │  Research   │ Robustness, Safe       │
│   Center    │  Explorer   │  Analyzer   │  Workbench  │ Failure & Viva Defense │
│  & Status   │   & DCN     │  & Offline  │   & Zero-   │                        │
│             │  5-Tuples   │    PCAP     │ Day Anomaly │                        │
└─────────────┴─────────────┴─────────────┴─────────────┴────────────────────────┘
```

---

### Minute 1 — Architecture, Operations Center & Leakage Safeguards
**Tab:** `🛡️ Overview`

#### Action:
1. Point to the **Status Bar** in the sidebar:
   - Engine: `ONLINE`
   - Flow Ingestion: `PCAP & Flow CSV`
   - Leakage Guard: `ENFORCED`
2. Point to the top **Executive KPI Cards**:
   - Holdout Macro-F1: `0.989` (Balanced Detection Score across attack classes)
   - False Alarm Rate: `1.59%`
   - Inference Latency: `0.016 ms` (~`15,240 flows/sec` local batch throughput)

#### What to Say:
> *"We start in the Executive Operations Center. Our champion model is a gradient-boosted tree ensemble (LightGBM). Notice our scientific guarantees: rather than reporting naive overall accuracy—which can be misleading due to class imbalance—we optimize for **Macro-Averaged F1-Score**. Furthermore, our pipeline enforces strict data isolation: standard scaling, median imputers, and threshold selection were fitted strictly inside cross-validation training folds using scikit-learn Pipelines. The holdout test set remained untouched until final evaluation."*

---

### Minute 2 — Flow Extraction & DCN Canonical 5-Tuples
**Tab:** `🔍 Dataset Explorer`

#### Action:
1. Select `CIC-IDS2017 Sample (Multi-Attack)` or `NetSentry Synthetic Demo`.
2. Scroll to the **Data Quality & Schema Assessment** KPI bar:
   - Total Records, Numeric Features, Infinite Values, Duplicate Rows, Detected Schema.
3. Scroll down to the **DCN Feature Glossary** accordion.

#### What to Say:
> *"Next, in the Dataset Explorer, we bridge machine learning with Data Communication & Networking (DCN). In high-speed networking, deep packet inspection (DPI) of every packet payload is computationally prohibitive and blocked by HTTPS/TLS encryption. Instead, NetSentry AI operates on **bidirectional network flows** aggregated using the canonical 5-Tuple:*
> - *Source IP, Destination IP, Source Port, Destination Port, and Layer 4 Protocol.*
> *Features like flow duration, packet inter-arrival times, bytes per second, and TCP control flags (SYN, RST, ACK) capture attack behaviors: a SYN flood manifests as high forward packets with zero backward acknowledgments, while low-and-slow pacing attempts to suppress transmission density."*

---

### Minute 3 — Traffic Analyzer, Offline PCAP Ingestion & Privacy Redaction
**Tab:** `🛰️ Traffic Analyzer`

#### Action:
1. **Curated Flow Stream Demo:**
   - Leave stream on `Curated Sample Flow Traffic`.
   - Point to the 5-column KPI bar: **Total Flows Scored, Flagged Threats, Critical Risk, High Risk, Quarantined**.
2. **Offline PCAP Ingestion Demo:**
   - Click the radio button: `Offline Packet Capture (PCAP/PCAPNG Ingestion)`.
   - Select `Included Sample Capture (data/sample/test_traffic.pcap)`.
   - The UI displays: `Reconstructed 3 flows from 8 packets (0.01s capture duration)`.
   - Expand `🔍 Inspect PCAP Extraction Summary` to show the reconstructed 5-tuples.
3. **Individual Flow Deep Inspection:**
   - Select a flagged flow record in the dropdown.
   - Point to the **Plain-English Security Incident Alert**:
     - Verdict, executive summary, and actionable SOC advice.
     - Expand `🔍 Inspect Underlying Flow Features & Normal Medians` to show the standard deviation z-scores.
4. **Privacy-Preserving Export:**
   - Point to the `🔒 Privacy Masking` checkbox.
   - Click `📥 Export Scored Telemetry to CSV` and explain that IPv4 host octets (`192.168.1.***`) and IPv6 endpoints (`2001:db8:85a3:****`) are masked to prevent tracking in shared audit logs.

#### What to Say:
> *"In the Traffic Analyzer, we demonstrate live end-to-end inference. NetSentry AI can ingest raw packet captures directly from disk. Here, we parse `test_traffic.pcap`: our Scapy engine reads the packet headers, pairs bidirectional packets by 5-tuple, and passes the reconstructed flow matrix into our champion pipeline.*
> *For security operations (SOC), an unexplained probability score is useless. NetSentry AI generates an automated plain-English narrative detailing exactly why a connection was flagged—for instance, an elevated forward packet rate 4 standard deviations above normal baseline—accompanied by actionable mitigation advice. Finally, when exporting logs, we automatically redact IP host octets for privacy compliance."*

---

### Minute 4 — Research Workbench: Domain Generalization & Zero-Day Anomalies
**Tab:** `🔬 Research Workbench`

#### Action:
1. Click **Tab 1: Cross-Dataset Domain Generalization**:
   - Point out the domain shift experiment: Training on CIC-IDS2017 and testing on UNSW-NB15.
   - Show the F1 degradation metric (-66.8% drop under naive transfer) and explain why: **concept inversion** in flow duration.
   - Mention the Joint Multi-Domain Pipeline that restored F1 to 0.8932.
2. Click **Tab 2: Unsupervised Anomaly Detection**:
   - Show the **Isolation Forest** benchmark:
   - High Recall (66.8%) on volumetric DoS attacks without any labels!
   - Blindness (0.0% recall) on stealth port scans that mimic benign protocol noise.

#### What to Say:
> *"In our Research Workbench, we investigate why models fail when deployed across different networks. In our cross-dataset experiments between CIC-IDS2017 and UNSW-NB15, a model with 98% in-domain accuracy collapsed to 31% F1 when evaluated on an unseen enterprise topology. Through feature ablation, we discovered concept inversion in flow duration: DoS attacks in CIC-IDS2017 are long volumetric floods, while exploits in UNSW-NB15 are sub-second bursts. We resolved this through joint multi-domain training.*
> *We also benchmark unsupervised Isolation Forest against zero-day attacks. Supervised models have zero recall on completely new attack families they were never trained on. Isolation Forest successfully detected 66.8% of volumetric attacks purely through geometric tree isolation depth, proving the necessity of a hybrid defense architecture."*

---

### Minute 5 — Robustness, Safe Failure Quarantine & Viva Defense
**Tab:** `🔬 Research Workbench` $\to$ Sub-tab: `🛡️ Robustness & Stress Workbench`

#### Action:
1. Point to the **Composite Resilience Scores**:
   - LightGBM: `37.2 / 100`, Random Forest: `34.7 / 100`.
   - Max Macro-F1 Drop: `-0.379` under 15% clock jitter.
2. Show the **Bar Chart of Clean vs Perturbed F1**:
   - Point to **Measurement Jitter (5%)**: F1 dropped from 0.989 to 0.662 (405 attacks flipped to benign).
   - Point to **Enterprise Jumbo Frames (MTU 9000)**: F1 dropped to 0.664 (33.3% flips).
3. Explain the **Safe Failure Policy Card**:
   - `INVALID_NON_FINITE` quarantine for $+\infty / -\infty$.

#### What to Say (The Strong Interview Closer):
> *"Finally, we stress-tested our models under physically defensible Data Communication and Networking disruptions. Standard academic papers report clean scores and ignore failure modes. We uncovered two critical vulnerabilities:*
> 1. *First, tree ensembles are brittle to continuous NIC clock jitter: adding just 5% timestamp noise flipped 405 attack flows into benign classifications, dropping F1 by 32%. This is because orthogonal tree splits partition tightly-clustered timing distributions with razor-thin margins.*
> 2. *Second, we solved the **Silent Benign Fallacy**: network flow meters produce positive or negative infinity when duration is zero due to division by zero. If a pipeline naively imputes infinity with median training values, it synthesizes an artificial normal flow and classifies a corrupt or malicious flow as 'safe'. In NetSentry AI, any non-finite rate is immediately quarantined with `prediction = -1` and `data_status = INVALID_NON_FINITE`, ensuring sensor failures trigger SOC review rather than silently bypassing detection.*
> *This concludes my demonstration. I would be glad to answer any questions about the networking protocols, feature engineering, or ML architectures."*

---

## 4. Emergency Fallback Plan (If Live Errors Occur)

```
========================================================================================================
                                     LIVE DEMO FALLBACK MATRIX
========================================================================================================
Potential Failure Scenario   Immediate Fallback Action                Technical Explanation to Give
--------------------------------------------------------------------------------------------------------
Model artifact missing       CLI: python -m netsentry.train --demo    "Regenerating champion model
(artifacts/best_model...)    --fast                                   pipeline from canonical demo data"
PCAP file upload fails       Switch radio to "Curated Sample Flow     "Switching to cached flow telemetry
                             Traffic (data/sample/demo_flows.csv)"    stream to demonstrate scoring"
Port 8501 already occupied   streamlit run app/main.py --server.port  "Launching dashboard on secondary
                             8502                                     loopback socket"
Browser renders warning      Refresh browser tab (Ctrl + F5)          "Streamlit hot-reload context
                             or run bare unittest                     reinitialization"
========================================================================================================
```

---

## 5. Research Artifacts vs Live Dashboard Attribution

To maintain scientific integrity during an interview:

```
========================================================================================================
                                     METRIC ATTRIBUTION MAP
========================================================================================================
Displayed Feature / Metric         Source Generation Mode      Supporting File / Script
--------------------------------------------------------------------------------------------------------
Interactive Flow Scoring           Live (Real-time in memory)  app/views/traffic_analyzer.py
Local Z-Score Narrative Alerts    Live (Real-time in memory)  src/netsentry/explainability/local_explainer
PCAP Packet Parsing & 5-Tuples     Live (Scapy execution)      src/netsentry/pcap/flow_extractor.py
LightGBM Holdout 0.9892 F1         Offline Research Benchmark  artifacts/phase6_experiment_results.json
Cross-Dataset Concept Inversion    Offline Research Benchmark  artifacts/phase6_experiment_results.json
5% Jitter Collapse (0.989 -> 0.662) Offline Research Benchmark  artifacts/phase7_robustness_results.json
Bayesian Alert Fatigue (94% false) Offline Research Benchmark  artifacts/phase5_audit_results.json
========================================================================================================
```

---

## 6. Screen Sharing & Presentation Privacy Checklist

Before sharing your screen or recording an interview presentation video, verify:
- [x] **No Internal IP Leakage:** The privacy masking checkbox is enabled by default in `Traffic Analyzer` to redact host octets (`192.168.1.***`).
- [x] **No Windows User Profile Leakage:** Log sanitizer strips `C:\Users\username\...` to `[USER_DIR]/`.
- [x] **No Cloud / Token Secrets:** No API keys or passwords exist in shell history or open VS Code tabs (`sanitize_log_message` scrubs all `password=`, `token=`, AWS keys).
- [x] **Terminal Cleanliness:** Clear terminal buffer (`cls` in PowerShell) before screen sharing.
- [x] **Clean Working Tree:** Run `git status` to ensure repository is clean and on tag `phase10-complete`.
