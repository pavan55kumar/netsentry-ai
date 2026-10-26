# NetSentry AI

A small, educational network-intrusion-detection project. It learns from **labeled network-flow rows** (one row per connection/flow), not individual packets. The initial run is intentionally synthetic, so you can learn the workflow without downloading a huge dataset.

> Important: demo results are only results on generated data. They do not show real intrusion-detection accuracy. Results on a public dataset depend on the data, labeling, feature choices, split strategy, and random seed.

## What you will learn

- How a flow CSV becomes numeric model inputs
- Why the `label` is kept out of the inputs
- How to compare Logistic Regression, Random Forest, Extra Trees, and Histogram Gradient Boosting
- Why accuracy alone can hide a bad intrusion detector
- How to save a model and score new flow rows

## Open and run in VS Code

1. Use Python 3.11, 3.12, or 3.13 for the smoothest package installation, then select it with **Python: Select Interpreter** in VS Code. Open this `netsentry-ai` folder in VS Code.
2. Open **Terminal → New Terminal** and run the following from this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m netsentry.train --demo
```

If PowerShell blocks activation, run this in that terminal once, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

The demo creates `artifacts/` containing:

- `best_model.joblib` — the selected trained pipeline
- `feature_names.json` — exact input-column order expected later
- `metrics.json` — precision, recall, macro-F1, false-positive rate, and confusion matrices
- `model_comparison.csv` — a compact comparison table
- `confusion_matrix.png` — a picture of the selected model's holdout results

The four training pipelines impute missing numbers **using training data only**. The Logistic Regression pipeline also scales only from training data. The project uses 5-fold cross-validation on the training portion to choose the saved model; the holdout test portion is not used for selection. This is why the transformations sit inside each pipeline.

## Read the metrics

For malicious traffic (the positive class):

- **Precision:** Of flows predicted malicious, how many really were malicious?
- **Recall:** Of actual malicious flows, how many were found?
- **Macro-F1:** A balanced score treating benign and malicious classes equally.
- **False-positive rate (FPR):** Of benign flows, what fraction were incorrectly flagged? High FPR causes alert fatigue.
- **Confusion matrix:** Shows true/false positives/negatives directly.

The project selects the model with the highest mean training-only cross-validation macro-F1 as a transparent default. That is not a deployment decision: in a real environment, choose a threshold/model after deciding the cost of missed attacks versus false alarms.

## Use a real public network-flow CSV

This repository does not download or train on a public dataset automatically. Download a labeled flow dataset yourself, read its license/card, and place a CSV under `data/real/` (the folder is ignored by Git). Examples often used for learning include [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset). Their column names and labels differ, so inspect them first.

Your input must have:

1. One label column with exactly two values, such as `BENIGN` and `ATTACK`.
2. Numeric flow-measurement columns, such as packet counts, bytes, duration, and flags.
3. No answer-revealing columns used as features. Do not use target/attack/category fields, IDs, capture timestamps, or dataset-specific fields that encode the answer.

Example (adjust the file path and label names to match your data):

```powershell
python -m netsentry.train --data data\real\flows.csv --label-column Label --positive-label ATTACK --drop-columns "Flow ID" Timestamp --artifacts-dir artifacts\real_run
```

The program automatically ignores non-numeric columns and drops suspicious names containing words such as `attack`, `class`, `category`, `label`, `target`, or `outcome`. It reports those decisions in `metrics.json`.

### Leakage warning

Before splitting, exact duplicate feature rows are removed so identical rows cannot appear on both sides. The default split is reproducible and stratified, meaning both benign and malicious traffic appear in train and test. It is still only a baseline. If records overlap by host/session or are ordered in time, random splitting can exaggerate performance. For serious evaluation, use a chronological split or a group split (for example, keep all flows from a host/session together) and document it.

## Score new flows

After training, score a new unlabeled CSV. It must contain every column listed in the saved `feature_names.json`:

```powershell
python -m netsentry.predict --data data\real\new_flows.csv --model artifacts\real_run\best_model.joblib --features artifacts\real_run\feature_names.json --output artifacts\real_run\predictions.csv
```

`prediction` is `0` for benign and `1` for malicious. `malicious_probability`, when present, is a model score — not a guaranteed probability of an attack.

## File guide

| File | Purpose |
| --- | --- |
| `src/netsentry/data.py` | Synthetic demo data, CSV loading, validation, duplicate removal, and splitting. |
| `src/netsentry/train.py` | Cross-validates and evaluates four baseline models; saves reports and the selected pipeline. |
| `src/netsentry/predict.py` | Loads the saved pipeline and scores new flows. |
| `tests/test_data.py` | Small smoke test for the data preparation rules. |
| `requirements.txt` / `pyproject.toml` | Python package setup and required libraries. |

## Sensible next steps

- Train on one well-documented public dataset and record its exact version and preprocessing.
- Add a time/group-aware split that matches your capture setup.
- Inspect class imbalance and use precision-recall curves to choose an alert threshold.
- Evaluate on a separate later capture, not just a random holdout.
- Never send unreviewed automated blocking decisions to a production firewall.



