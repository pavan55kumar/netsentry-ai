# NetSentry AI — Phase 7: Security Engineering & System Reliability Audit

**Author:** NetSentry AI Security & Machine Learning Engineering Team  
**Persona Context:** 3rd-Year B.Tech Information Science & Engineering Student Portfolio  
**Audit Baseline Commit:** `91525662a6ad471406668a5ec9ccd5ca5d80957f` (Tag: `phase6-complete`)  
**Completed Commit Target:** Phase 7 Verification Checkpoint (Tag: `phase7-complete`)  
**Test Suite Status:** 44 / 44 Unit & Reliability Tests Passing (14.35s execution time)

---

## 1. Executive Summary & Audit Scope

In network intrusion detection systems (NIDS), high benchmark accuracy on clean, pre-packaged academic datasets often conceals critical real-world failure modes. In live deployments, network sensors produce missing timestamps, hardware counter overflows, non-IP frames, corrupted headers, and zero-duration rate calculations. Furthermore, adversaries deliberately pace attack packets (e.g., Slowloris) or exploit fragile machine learning thresholds to evade detection.

**Phase 7** executes an exhaustive security engineering and reliability upgrade across the entire NetSentry AI platform. The objectives achieved include:

1. **Independent Pre-Modification Audit:** Re-evaluated the Git repository state and verified all 30 Phase 6 baseline tests prior to making modifications.
2. **Input Validation & Safe Failure Architecture:** Eliminated silent failure modes. Malformed records, infinite flow rates, and missing schema features are explicitly validated; severely corrupted rows are isolated as `UNPARSEABLE_ANOMALY` rather than silently imputed as normal/benign traffic.
3. **PCAP & Network-Flow Robustness:** Hardened the 5-tuple flow reconstruction engine against 0-byte captures, corrupted header magic bytes, non-IP frames (ARP, STP), and inter-packet idle timeouts.
4. **Model Output Reliability & Prediction Calibration:** Resolved inverted Isolation Forest predictions ($+1 \to \text{Benign}, -1 \to \text{Anomaly}$), enforced probability bounds $[0, 1]$, and formally decoupled geometric anomaly scores from calibrated class probabilities.
5. **Privacy-Preserving Structured Operational Logging:** Implemented automated regex redaction for IPv4 host octets (`192.168.1.***`), credentials, bearer tokens, and local user filesystem directories.
6. **Temporary File Isolation & System Hygiene:** Secured uploaded PCAP and CSV workflows in Streamlit with 50 MB limits and deterministic `try...finally` temporary file unlinking.

---

## 2. Pre-Modification Audit & Verification (Objective 1)

### 2.1 Git State & Working Tree Audit
Prior to code edits, the repository state was independently inspected:
- **Active Commit:** `91525662a6ad471406668a5ec9ccd5ca5d80957f`
- **Active Tag:** `phase6-complete`
- **Git Tree:** Clean (zero uncommitted diffs or untracked operational files)
- **Baseline Test Execution:**
  ```powershell
  .\.venv\Scripts\python.exe -m unittest discover -s tests -v
  ```
  **Outcome:** Ran 30 tests in 9.389s — **30 PASSED, 0 FAILED**.

### 2.2 Phase 6 Results Verification & Inconsistencies Audited
An audit of Phase 6 artifacts (`artifacts/phase6_experiment_results.json`) revealed the following findings:
- **Champion Model:** LightGBM achieved Macro-F1 = 0.9892, Balanced Accuracy = 0.9887, and FPR = 1.59% on clean holdout splits.
- **Unseen-Attack Vulnerability Confirmed:** Supervised Random Forest demonstrated 0.0% recall when evaluating completely held-out attack families (DoS, PortScan, WebAttack, Botnet). Isolation Forest demonstrated 66.8% recall on DoS attacks, proving the necessity of hybrid defense.
- **Cross-Domain Feature Alignment Discrepancy:** Cross-dataset experiments between CIC-IDS2017 and UNSW-NB15 collapsed to F1 = 0.315 under direct transfer due to duration scaling differences ($\mu\text{s}$ vs $\text{ms}$), which was resolved via the joint multi-domain pipeline (+0.578 F1 improvement to 0.893).
- **Silent Prediction Risk Identified:** The pre-existing `predict.py` scoring function used `pd.to_numeric(errors="coerce")` followed directly by `model.predict(X)`. If an uploaded row had 100% invalid strings (all converted to `NaN`), the pipeline imputer filled them with median training values, silently classifying corrupted data as **benign normal traffic**. This security flaw was prioritized for remediation.

---

## 3. Input Validation & Safe Failure Architecture (Objective 2)

### 3.1 The Vulnerability: The Silent Benign Fallacy
In cybersecurity ML, the default reaction to unparseable data must never be to report the traffic as "Safe" or "Benign":
```
[Corrupted / Truncated Flow] 
        ↓ (pd.to_numeric errors="coerce")
[All Features = NaN] 
        ↓ (SimpleImputer median fill)
[Synthetic Normal Flow] 
        ↓ (Classifier Predict)
[Prediction = 0 (BENIGN)]  <-- CRITICAL VULNERABILITY!
```
An attacker could intentionally append junk bytes to crash feature extractors, causing malicious traffic to be marked as clean.

### 3.2 Implemented Fix: Safe Isolation via `score_flows`
In [`src/netsentry/predict.py`](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/src/netsentry/predict.py), we introduced explicit input validation and safe failure boundaries:

1. **Empty Input Guard:**
   ```python
   if len(frame) == 0:
       result["prediction"] = pd.Series(dtype=int)
       result["risk_level"] = pd.Series(dtype=str)
       result["malicious_score"] = pd.Series(dtype=float)
       return result
   ```
2. **Schema Mismatch Exception:**
   If expected features are missing, `SchemaMismatchError` (subclass of `ValueError`) is raised immediately with the missing column names, halting execution safely.
3. **Infinite Value Sanitization:**
   Flow exporters frequently divide packet bytes by flow duration. If duration is $0.0$, standard floating-point operations produce `np.inf` or `-np.inf`. Scikit-learn pipelines with `SimpleImputer` crash when encountering infinities. We sanitize them immediately:
   ```python
   X_raw = frame[list(expected_features)].apply(pd.to_numeric, errors="coerce")
   X = X_raw.replace([np.inf, -np.inf], np.nan)
   ```
4. **Severe Corruption Quarantine:**
   We compute row-wise missingness ratios:
   $$\text{corrupt\_ratio}_i = \frac{1}{D} \sum_{j=1}^D \mathbb{I}(X_{i,j} = \text{NaN})$$
   If $\text{corrupt\_ratio}_i > 0.80$ (configurable via `max_corrupt_ratio`), the row is quarantined:
   - `prediction = -1`
   - `risk_level = "UNPARSEABLE_ANOMALY"`
   - `malicious_score = np.nan`
   This guarantees corrupted flows trigger SOC inspection rather than masquerading as normal network traffic.

---

## 4. PCAP & Network-Flow Robustness (Objective 3)

### 4.1 PCAP Ingestion Vulnerabilities Audited
Raw packet capture parsing with Scapy faces multiple failure vectors:
- **0-Byte Files:** Cause low-level `EOFError` or internal `Scapy_Exception`.
- **Corrupted Headers:** Files with missing or invalid magic bytes (e.g. text files renamed to `.pcap`) crash deserializers.
- **Non-IP Traffic:** Layer 2 protocols (ARP, STP, LLDP, CDP) do not possess IP 5-tuples.
- **Unbounded Flow Boundaries:** Packets with identical 5-tuples separated by hours or days would be coalesced into a single unphysical flow.

### 4.2 Implemented Fixes in `flow_extractor.py`
In [`src/netsentry/pcap/flow_extractor.py`](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/src/netsentry/pcap/flow_extractor.py):

1. **Magic Number Header Verification:**
   Before launching packet parsers, file headers are validated against authentic capture signatures:
   - PCAP Little-Endian: `0xd4 0xc3 0xb2 0xa1`
   - PCAP Big-Endian: `0xa1 0xb2 0xc3 0xd4`
   - PCAP Nanosecond: `0x4d 0x3c 0xb2 0xa1` / `0xa1 0xb2 0x3c 0x4d`
   - PCAPNG Section Header Block: `0x0a 0x0d 0x0d 0x0a`
   Invalid headers raise custom `CorruptPcapError`; 0-byte captures raise `EmptyPcapError`.
2. **Idle Timeout Flow Splitting:**
   Matching hardware NetFlow / IPFIX flow meters, an `idle_timeout_sec = 120.0` parameter tracks packet inter-arrival silence. If $\Delta t > 120\text{s}$, the existing flow record is finalized and a new flow record begins.
3. **Non-IP Frame Isolation:**
   Non-IP frames are counted under `protocols_encountered["NON_IP"]` and recorded in extraction warnings without crashing.
4. **Canonical Column Preservation:**
   If a capture contains 0 valid IP flows, `extract_flows_from_pcap` returns an empty DataFrame populated with `CANONICAL_FLOW_COLUMNS` rather than an empty 0-column structure, preventing downstream schema mismatch crashes.

---

## 5. Model Output Reliability & Prediction Calibration (Objective 5)

### 5.1 Isolation Forest Inlier/Outlier Alignment
The scikit-learn convention for `IsolationForest.predict` is:
- $+1$: Inlier (Normal baseline traffic)
- $-1$: Outlier (Anomalous traffic)

In early implementations, `(prediction == 1)` was checked across all models, inadvertently treating **inliers as attacks and anomalies as benign**!

**Remediation:**
In `score_flows`, we detect `IsolationForest` estimators and explicitly map:
$$\text{prediction} = \begin{cases} 0 & \text{if raw } = +1 \text{ (Normal Inlier)} \\ 1 & \text{if raw } = -1 \text{ (Anomalous Outlier)} \end{cases}$$
Furthermore, anomaly scores are derived from `decision_function` (inverted so higher values represent stronger outlier magnitude) and assigned the risk tier `HIGH` if an anomaly is detected.

### 5.2 Decoupling Anomaly Scores from Calibrated Probabilities
- **Supervised Models (LightGBM, Random Forest, Logistic Regression):** Output class probabilities $P(Y=1 \mid X) \in [0, 1]$. Tiers:
  - `CRITICAL`: $\ge 0.85$
  - `HIGH`: $\ge 0.60$
  - `MEDIUM`: $\ge 0.40$
  - `LOW`: $< 0.40$
- **Unsupervised Anomaly Detectors (Isolation Forest):** Decision scores represent partition depths in random trees. They are **not** probabilities. The UI and documentation explicitly label these as uncalibrated geometric outlier scores.

---

## 6. Privacy, Operational Logging & File Hygiene (Objective 6)

### 6.1 Structured Operational Logging (`netsentry.utils.logging`)
We created [`src/netsentry/utils/logging.py`](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/src/netsentry/utils/logging.py) to implement strict privacy and security filtering:
- **IPv4 Host Octet Masking:**
  $$\text{192.168.1.45} \longrightarrow \text{192.168.1.***}$$
  Subnet identifiers are preserved for network topology context while individual endpoint identities are protected.
- **Credential Scrubbing:**
  Regex filters scrub `password=...`, `token=...`, `api_key: ...`, AWS access keys (`AKIA...`), and Bearer tokens, replacing them with `[REDACTED_SECRET]`.
- **Local Directory Scrubbing:**
  Personal Windows user paths (`C:\Users\username\...`) are stripped to `[USER_DIR]/...` to prevent environment leakage in distributed audit logs.
- **Log Rotation:**
  Rotates at 5 MB with 3 retained backups to protect storage on analyst laptops.

### 6.2 Temporary File Hygiene in Web Interface
In [`app/views/traffic_analyzer.py`](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/app/views/traffic_analyzer.py):
- Uploaded PCAP and CSV files are constrained to $\le 50\text{ MB}$.
- Temporary files created on disk for Scapy ingestion are wrapped in a deterministic `try...finally` block that unlinks (`target_pcap_path.unlink()`) immediately upon extraction completion, preventing temporary file accumulation.

---

## 7. Automated Test Suite Verification (Objective 7)

We added [`tests/test_phase7.py`](file:///c:/Users/ASUS/Documents/Codex/2026-10-25/referenced-chatgpt-conversation-this-is-an/outputs/netsentry-ai/tests/test_phase7.py), introducing 14 new automated unit and reliability tests.

### Test Execution Command
```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### Verified Test Outcome
```
----------------------------------------------------------------------
Ran 44 tests in 14.349s

OK
```
All 30 baseline tests + 14 Phase 7 security tests pass cleanly without errors or skips.

| Test Module | Test Name | Target Verified | Status |
| :--- | :--- | :--- | :--- |
| `test_phase7` | `test_empty_dataframe_handled_safely` | Empty DataFrame produces structured empty output | **PASS** |
| `test_phase7` | `test_missing_expected_features_raises_schema_mismatch` | Missing columns raise `SchemaMismatchError` | **PASS** |
| `test_phase7` | `test_infinite_values_sanitized_during_scoring` | `np.inf` sanitized to finite scores | **PASS** |
| `test_phase7` | `test_severe_corruption_isolated_as_unparseable` | Corrupted rows isolated as `UNPARSEABLE_ANOMALY` | **PASS** |
| `test_phase7` | `test_isolation_forest_inlier_outlier_prediction_consistency` | Isolation Forest predictions mapped consistently | **PASS** |
| `test_phase7` | `test_empty_pcap_raises_empty_pcap_error` | 0-byte PCAP raises `EmptyPcapError` | **PASS** |
| `test_phase7` | `test_corrupt_pcap_header_raises_corrupt_pcap_error` | Bad magic bytes raise `CorruptPcapError` | **PASS** |
| `test_phase7` | `test_canonical_flow_columns_on_empty_flow_result` | 0 reconstructed flows preserve canonical columns | **PASS** |
| `test_phase7` | `test_ipv4_host_octet_redaction` | IP host octets redacted to `***` | **PASS** |
| `test_phase7` | `test_secret_and_credential_scrubbing` | Passwords, tokens, API keys scrubbed | **PASS** |
| `test_phase7` | `test_user_path_sanitization` | Local Windows directories redacted | **PASS** |
| `test_phase7` | `test_gaussian_noise_preserves_physical_positivity` | Noise respects physical non-negativity ($\ge 0$) | **PASS** |
| `test_phase7` | `test_missing_feature_injection_preserves_shape` | Missingness injection preserves matrix dimensions | **PASS** |
| `test_phase7` | `test_adversarial_pacing_attenuation` | Rate pacing dilates duration and drops rate | **PASS** |

---

## 8. Remaining Risks & Operational Limitations

1. **Hardware Capture Capabilities:** Scapy operates as a user-space Python packet parser. For wire-speed 10 Gbps / 100 Gbps live wire capture, dedicated kernel bypass tools (e.g., DPDK, AF_PACKET, or TShark) must be utilized. NetSentry AI explicitly documents this boundary and provides `get_tshark_extraction_command` for external high-speed flow export.
2. **Adversarial Noise Brittleness:** As revealed in our robustness experiments, tree-based models (LightGBM and Random Forest) exhibit significant F1 drops under 5% continuous measurement jitter. Mitigating this requires noise-augmented training or interval discretization, which forms a primary research recommendation for future phases.
3. **Encrypted Payload Inspection:** NetSentry AI focuses strictly on L3/L4 transport flow metadata (packet timing, sizes, TCP flags). It does not perform deep packet inspection (DPI) on TLS/HTTPS encrypted payloads.
