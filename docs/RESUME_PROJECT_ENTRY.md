# NetSentry AI — Resume & Portfolio Project Entries

This document provides three concise, technically rigorous, and truthful project descriptions for resumes, CVs, and professional LinkedIn/portfolio profiles. All bullet points reflect verified engineering contributions and benchmark evidence without exaggeration.

---

## 📄 Option 1: Two-Bullet Resume Entry (Compact / Space-Constrained)

**NetSentry AI — Network Intrusion Detection & ML Research Platform** | *Python, scikit-learn, LightGBM, Scapy, Streamlit*
- Architected an intrusion detection pipeline evaluating 11 ML models on CIC-IDS2017 and UNSW-NB15 datasets; achieved 0.989 holdout Macro-F1 with LightGBM (0.016 ms/flow latency) using zero-leakage scikit-learn pipelines.
- Engineered offline PCAP flow reconstruction (5-tuple aggregation, 120s session timeout), uncovered a 66.8% cross-dataset transfer collapse via feature ablation, and stress-tested physical timing jitter, backed by 63 automated regression tests.

---

## 📄 Option 2: Three-Bullet Detailed Resume Entry (Recommended for SWE / MLE / Security Internships)

**NetSentry AI — Machine Learning Network Intrusion Detection Research Platform** | *Python, pandas, scikit-learn, LightGBM, Scapy, Streamlit*
- **Leakage-Free ML Pipeline:** Built a modular pipeline benchmarking 11 supervised and unsupervised models (LightGBM, Random Forest, Isolation Forest) on CIC-IDS2017 flow telemetry; achieved 0.9892 holdout Macro-F1 and 1.59% FPR with scalers, imputers, and threshold tuning fitted strictly within training folds.
- **DCN Flow Ingestion & Generalization Research:** Implemented offline PCAP ingestion aggregating raw packets into bidirectional 5-tuple flows; discovered cross-dataset performance dropped from 0.9488 to 0.3148 F1 between CIC-IDS2017 and UNSW-NB15 due to concept inversion in flow duration, resolved to 0.8932 F1 via joint multi-domain training.
- **Robustness Testing & Safe Failure Engineering:** Stress-tested model resilience under 5 physical network perturbations, revealing that $\pm 5\%$ clock jitter collapses tree F1 to 0.6617 by crossing axis-aligned split boundaries; implemented safe failure quarantining for non-finite rates (+Inf/-Inf) and authored a 63-test regression suite.

---

## 💼 Option 3: LinkedIn / Portfolio Project Description (For GitHub, Personal Website, or LinkedIn Project Section)

**Project Name:** NetSentry AI — Machine Learning Network Intrusion Detection Research Platform  
**Associated Education:** B.Tech in Information Science & Engineering, NMAM Institute of Technology, Nitte  
**Technologies:** Python 3.12, scikit-learn, LightGBM, XGBoost, pandas, NumPy, Scapy, Streamlit, SHAP  

**Project Summary:**
NetSentry AI is a machine-learning-based network intrusion detection research platform exploring the intersection of Data Communication & Networking (DCN) and applied machine learning. The project analyzes bidirectional flow metadata (NetFlow/IPFIX statistics) to classify network threats without inspecting encrypted packet payloads.

**Key Engineering Contributions & Research Findings:**
1. **Zero-Leakage Training Architecture:** Constructed scikit-learn pipelines encapsulating median imputation, feature scaling, and validation-based threshold optimization strictly within training folds, ensuring zero data leakage into holdout evaluations.
2. **Offline PCAP Flow Aggregation:** Built an offline packet capture processor using Scapy that groups raw packets into bidirectional flows via canonical 5-tuples (Src IP, Dst IP, Src Port, Dst Port, Protocol) and enforces a 120-second idle session timeout.
3. **Cross-Dataset Generalization & Concept Inversion:** Investigated domain transfer from CIC-IDS2017 to UNSW-NB15, discovering an empirical 66.8% Macro-F1 collapse (0.9488 to 0.3148). Feature ablation proved that opposing feature semantics (long-duration DoS floods in CIC vs sub-second exploit bursts in UNSW) caused the drop, which was mitigated to 0.8932 F1 using joint multi-domain training.
4. **Physical Robustness & Brittleness Analysis:** Stress-tested the champion LightGBM model across 5 physically grounded network perturbations. Demonstrated that $\pm 5\%$ continuous timing jitter causes 405 attack flows to flip to benign (F1 drops to 0.6617) due to orthogonal tree split boundaries partitioning deterministic attack intervals.
5. **Operational Reliability & Safe Input Handling:** Implemented an automated quarantine policy for non-finite rate divisions (+Inf/-Inf) and corrupted rows, privacy-preserving IP host redaction (`192.168.1.***`), log secret scrubbing, and an interactive 8-view Streamlit SOC dashboard with local explainability.
6. **Rigorous Quality Gate:** Verified complete reproducibility across 63 automated unit, integration, and security tests.

*All metrics are verified research benchmarks documented with full artifact provenance.*
