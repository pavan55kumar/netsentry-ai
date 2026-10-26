# NetSentry AI — Troubleshooting & FAQ Guide

## 1. Windows PowerShell & Environment Issues

### Issue 1: Script execution blocked by PowerShell
**Symptom:**
```powershell
.\.venv\Scripts\Activate.ps1 : File cannot be loaded because running scripts is disabled on this system.
```
**Resolution:**
Run this command once in your current PowerShell terminal session to bypass the restriction safely:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
Then re-run:
```powershell
.\.venv\Scripts\Activate.ps1
```

---

### Issue 2: VS Code using the wrong Python interpreter
**Symptom:**
ModuleNotFoundError for `pandas`, `scikit-learn`, or `netsentry`.
**Resolution:**
1. Press `Ctrl + Shift + P` in VS Code.
2. Type and select: **Python: Select Interpreter**.
3. Choose the `.venv` interpreter:
   `c:\Users\...\netsentry-ai\.venv\Scripts\python.exe`
4. Open a fresh terminal (`Terminal → New Terminal`).

---

### Issue 3: Launching the Web Interface
**Command:**
```powershell
.\.venv\Scripts\streamlit.exe run app/main.py
```
Or if `.venv` is activated:
```powershell
streamlit run app/main.py
```
The browser will automatically open at `http://localhost:8501`.

---

## 2. Machine Learning & Data Troubleshooting

### Issue 4: Input is missing trained feature columns
**Symptom:**
```
ValueError: Input is missing trained feature columns: ['flow_bytes_per_second', ...]
```
**Cause:**
Inference inputs must contain the identical numeric feature column names that the model was trained on.
**Resolution:**
Check `artifacts/feature_names.json` to inspect the exact column names expected by the champion pipeline.

---

### Issue 5: Infinite values in dataset caused training failure
**Symptom:**
```
ValueError: Input contains NaN, infinity or a value too large for dtype('float64').
```
**Cause:**
Network flow rate features (`flow_bytes_per_second`, `flow_packets_per_second`) divide total packets/bytes by duration. If flow duration is 0, float division yields `np.inf`.
**Resolution:**
NetSentry AI's `prepare_data` automatically replaces `[np.inf, -np.inf]` with `np.nan` and median-imputes them using training data statistics.

---

### Issue 6: Student Laptop Performance / Memory Limits
**Symptom:**
Training 500-tree ensembles takes several minutes or causes fan spin-up.
**Resolution:**
Use the `--fast` flag during CLI execution, or check the **⚡ Fast Laptop Mode** toggle in the Streamlit **Model Lab**. This reduces ensemble trees from 500 to 100, providing sub-second execution with virtually identical educational insights.

---

## 3. Phase 7: Security Engineering & PCAP Ingestion Issues

### Issue 7: Empty or Corrupted PCAP Uploads
**Symptom:**
```
netsentry.pcap.flow_extractor.EmptyPcapError: PCAP file 'test.pcap' is empty (0 bytes).
netsentry.pcap.flow_extractor.CorruptPcapError: File 'test.pcap' does not start with valid PCAP/PCAPNG magic header.
```
**Cause:**
Uploaded capture files are either 0 bytes (e.g. empty recording tap) or do not contain valid libpcap/pcapng header magic bytes (e.g. text logs mistakenly saved with a `.pcap` extension).
**Resolution:**
1. Check that the capture file starts with valid magic bytes (`0xd4c3b2a1` or `0x0a0d0d0a`).
2. Verify capture packet contents using Wireshark or `tcpdump -r <file> -c 5`.
3. Ensure file size is $> 0$ bytes and $\le 50$ MB for web app ingestion.

---

### Issue 8: Flow Record Flagged as `UNPARSEABLE_ANOMALY`
**Symptom:**
Prediction output displays `prediction = -1` and `risk_level = "UNPARSEABLE_ANOMALY"`.
**Cause:**
In Phase 7, NetSentry AI enforces a **Safe Failure Architecture**. If an input flow contains $> 80\%$ missing (`NaN`) or non-numeric corrupted values, the system quarantines the row rather than silently imputing fake normal values that would misleadingly report an attack as benign traffic.
**Resolution:**
1. Review the flow extraction logs to identify missing telemetry fields.
2. In the Streamlit **Traffic Analyzer**, inspect the raw flow table to verify that feature columns contain valid numeric counts.
3. For operational SOC triage, treat `UNPARSEABLE_ANOMALY` records as sensor telemetry alarms requiring forensic inspection.

---

### Issue 9: Schema Mismatch Between PCAP Extractor and Trained Model
**Symptom:**
```
SchemaMismatchError: Input is missing trained feature columns: ['Bwd Packet Length Min', ...]
```
**Cause:**
NetSentry AI's lightweight PCAP extractor outputs the standard **8-feature NetSentry schema** (`flow_duration_ms`, `total_fwd_packets`, `flow_bytes_per_second`, etc.), whereas models trained on full academic CIC-IDS2017 require the full **77-feature schema**.
**Resolution:**
1. In the **Model Lab**, train a model on the 8-feature NetSentry schema (`data/sample/demo_flows.csv`).
2. Alternatively, use `tshark` or `cicflowmeter` to extract the full 77-feature schema for academic models.

---

### Issue 10: Temporary File Cleanup on Student Laptops
**Symptom:**
Concern about uploaded PCAP files consuming storage space in system temp folders.
**Resolution:**
In Phase 7, all uploaded PCAPs are wrapped in deterministic `try...finally` blocks in `traffic_analyzer.py` that immediately unlink and delete temporary capture files from disk once 5-tuple flow aggregation is complete.

