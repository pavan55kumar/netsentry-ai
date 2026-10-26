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
