# NetSentry AI — Operations, Monitoring & Troubleshooting Runbook

**Version:** NetSentry AI v2.1.0 (Phase 8 Production Quality)  
**Target Environment:** Local Workstations, Academic Research Labs, Demo Environments  
**Logging Subsystem:** [`src/netsentry/utils/logging.py`](file:///src/netsentry/utils/logging.py)  

---

## 1. Operational Overview & Service Management

NetSentry AI provides both a modular Python library (`netsentry`) and an interactive Streamlit operations center (`app/main.py`).

### 1.1 Service Lifecycle Commands

| Action | PowerShell Command (Windows) | Bash Command (Linux/macOS) | Description |
| :--- | :--- | :--- | :--- |
| **Start Web Interface** | `.\.venv\Scripts\streamlit.exe run app/main.py` | `streamlit run app/main.py` | Launches local dashboard on port 8501 |
| **Start Custom Port** | `.\.venv\Scripts\streamlit.exe run app/main.py --server.port 8502` | `streamlit run app/main.py --server.port 8502` | Launches on alternate port if 8501 is occupied |
| **Stop Web Interface** | `Ctrl + C` in active terminal | `Ctrl + C` in active terminal | Shuts down Streamlit server gracefully |
| **Execute Full Test Suite** | `.\.venv\Scripts\python.exe -m unittest discover -s tests -v` | `python -m unittest discover -s tests -v` | Runs all 56 unit and integration quality gates |
| **Run Performance Benchmarks** | `.\.venv\Scripts\python.exe artifacts/run_phase8_performance_benchmarks.py` | `python artifacts/run_phase8_performance_benchmarks.py` | Measures latency, throughput, and memory |
| **Run Robustness Suite** | `.\.venv\Scripts\python.exe artifacts/run_phase7_robustness_experiments.py` | `python artifacts/run_phase7_robustness_experiments.py` | Measures jitter, dropout, and safe failure |
| **CLI Model Training** | `.\.venv\Scripts\python.exe src/netsentry/train.py` | `python src/netsentry/train.py` | Trains champion pipeline via CLI |

---

## 2. Resource Constraints & Safety Safeguards

To prevent memory exhaustion, Denial-of-Service (DoS) on the local host, and temporary file accumulation:

### 2.1 File Upload Constraints
- **Maximum File Size:** Constrained to **50 MB** for both CSV flow datasets and PCAP/PCAPNG packet captures in [`app/views/traffic_analyzer.py`](file:///app/views/traffic_analyzer.py).
- **Temporary Disk Hygiene:** Uploaded files stored in temporary disk locations are deterministically deleted via `try...finally: target_pcap_path.unlink()`. No residual `.pcap` files remain on disk after parsing completes.

### 2.2 Memory Footprint & Throughput
Based on our verified Phase 8 empirical benchmarks:
- **Peak Process Memory:** $\approx 51.7\text{ MB}$ during 5,000-flow batch scoring and PCAP parsing.
- **Single-Flow Latency:** Median = $70.16\text{ ms}$, Mean = $72.77\text{ ms}$.
- **Batch Processing Throughput:** $10,026\text{ flows/second}$ on standard 16-thread CPU.

---

## 3. Troubleshooting Matrix: Common Operational Issues

### Issue 1: `SchemaMismatchError: Input is missing trained feature columns...`
- **Symptom:** The Traffic Analyzer or API raises `SchemaMismatchError` when scoring an uploaded CSV or extracted PCAP.
- **Root Cause:** The active champion model was trained on a specific feature schema (e.g. 77 features from CIC-IDS2017), but the uploaded CSV provides a different schema family (e.g. 8 features from the NetSentry demo).
- **Resolution:**
  1. In the **Traffic Analyzer**, inspect the error message to view the expected features.
  2. If analyzing demo traffic or custom PCAP, navigate to the **Model Lab** and train/select a matching model on `data/sample/demo_flows.csv`.
  3. Ensure column names in your CSV do not have leading or trailing whitespace (`df.columns = df.columns.str.strip()`).

---

### Issue 2: `CorruptPcapError: File lacks valid PCAP/PCAPNG magic bytes`
- **Symptom:** Ingesting a packet capture fails immediately with `CorruptPcapError`.
- **Root Cause:** The uploaded file has a `.pcap` extension but contains invalid header bytes (e.g. a plain text file, HTML error page, or corrupted transfer).
- **Resolution:**
  1. Inspect the file magic bytes using Python:
     ```python
     with open("capture.pcap", "rb") as f:
         header = f.read(4)
         print(header.hex())
     ```
  2. Valid signatures recognized by NetSentry AI:
     - Little-Endian PCAP: `d4c3b2a1`
     - Big-Endian PCAP: `a1b2c3d4`
     - Nanosecond PCAP: `4d3cb2a1` / `a1b23c4d`
     - PCAPNG Section Header: `0a0d0d0a`
  3. If invalid, re-export the capture from Wireshark or `tcpdump` using standard libpcap format:
     ```bash
     tcpdump -r broken.pcap -w fixed.pcap
     ```

---

### Issue 3: `EmptyPcapError: Capture file is 0 bytes`
- **Symptom:** `EmptyPcapError: Capture file '...' is 0 bytes.`
- **Root Cause:** A live packet capture was interrupted before writing headers, or an empty file was created.
- **Resolution:** Confirm packet capture commands ran with root/admin privileges and captured at least one packet before stopping.

---

### Issue 4: `WARNING: No libpcap provider available ! pcap won't be used`
- **Symptom:** A Scapy warning prints to the terminal when importing `netsentry.pcap.flow_extractor`.
- **Root Cause:** Windows system does not have Npcap installed, or Scapy cannot bind to live network drivers.
- **Is this fatal?** **NO.** This warning relates strictly to live promiscuous wire capture. For NetSentry AI offline PCAP parsing, Scapy utilizes native Python binary deserializers and functions with 100% correctness.
- **Optional Fix:** To suppress the warning or enable live interface scanning, install [Npcap for Windows](https://npcap.com/) with "WinPcap API-compatible Mode" enabled.

---

### Issue 5: PowerShell `Execution_Policies` Script Activation Error
- **Symptom:** Running `.\.venv\Scripts\Activate.ps1` produces:
  `...cannot be loaded because running scripts is disabled on this system.`
- **Root Cause:** Windows PowerShell default execution policy restricts unsigned local scripts.
- **Resolution:** Execute in your current PowerShell session:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\.venv\Scripts\Activate.ps1
  ```

---

### Issue 6: `Port 8501 is already in use`
- **Symptom:** Streamlit fails to start because port 8501 is bound to another process.
- **Resolution:**
  ```powershell
  # Launch on alternative port
  .\.venv\Scripts\streamlit.exe run app/main.py --server.port 8502
  ```
  Or identify and terminate the orphaned process:
  ```powershell
  Get-Process -Id (Get-NetTCPConnection -LocalPort 8501).OwningProcess | Stop-Process
  ```

---

### Issue 7: Quarantined Rows Appearing in Telemetry (`prediction = -1`)
- **Symptom:** Scored telemetry contains rows with `prediction = -1` and `data_status = INVALID_NON_FINITE`.
- **Is this a bug?** **NO — this is an intentional security safeguard.**
- **Explanation:** The row contains $+ \infty$ or $- \infty$ (typically caused by a zero-duration rate calculation where bytes are divided by $0.0\text{ ms}$).
- **Action:** Under the NetSentry AI Safe Failure Policy, automated classification is suppressed to eliminate the silent benign failure vulnerability. Check the sensor flow exporter for clock counter resets or division by zero.

---

## 4. Privacy, Auditing & Log Rotation

NetSentry AI logs operational diagnostic messages via `src/netsentry/utils/logging.py`.

### 4.1 Automated Privacy Redactions
Logs and exported telemetry automatically sanitize sensitive information:
1. **IPv4 Host Octets:** Masks host identifiers (`192.168.1.45` $\to$ `192.168.1.***`), protecting endpoint identities while preserving subnet routing topology.
2. **Secret Scrubbing:** Regex filters intercept credentials (`password=...`, `token=...`, `AKIA...`) and replace them with `[REDACTED_SECRET]`.
3. **Filesystem Path Sanitization:** Windows user directories (`C:\Users\username\...`) are stripped to `[USER_DIR]/...` to prevent username leakage in public audit logs.

### 4.2 Log Rotation Policy
- **Maximum File Size:** 5 MB.
- **Backup Retention:** 3 historical rotated logs (`netsentry.log.1`, `netsentry.log.2`, `netsentry.log.3`).
- **Storage Protection:** Prevents runaway logging from consuming disk space on analyst laptops.

---

## 5. Architectural Boundaries & Security Disclaimer

1. **User-Space vs Kernel-Space:** NetSentry AI operates in user-space Python. It is an ML research, evaluation, and forensics platform. For wire-speed 10 Gbps / 100 Gbps live wire capture, dedicated kernel bypass tools (DPDK, AF_PACKET, TShark) must be utilized to export flow records.
2. **Encrypted Payload Boundary:** NetSentry AI analyzes L3/L4 transport flow metadata (packet timing, sizes, flags). It does not decrypt or inspect TLS/HTTPS encrypted application payloads.
3. **Human-in-the-Loop Requirement:** Model predictions represent statistical similarity to training distributions; they do **not** constitute mathematical proof of malice. Never configure an automated firewall to drop mission-critical traffic based on uncalibrated ML scores alone.
