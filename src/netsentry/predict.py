"""Score new numeric network-flow rows with a saved NetSentry model."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import joblib
import pandas as pd

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="artifacts/best_model.joblib")
    parser.add_argument("--features", default="artifacts/feature_names.json")
    parser.add_argument("--data", required=True, help="Unlabeled CSV of flows to score.")
    parser.add_argument("--output", default="artifacts/predictions.csv")
    args = parser.parse_args()
    expected = json.loads(Path(args.features).read_text(encoding="utf-8"))
    frame = pd.read_csv(args.data, low_memory=False)
    missing = [name for name in expected if name not in frame.columns]
    if missing: raise ValueError("Input is missing trained feature columns: " + ", ".join(missing))
    X = frame[expected].apply(pd.to_numeric, errors="coerce")
    model = joblib.load(args.model)
    result = frame.copy(); result["prediction"] = model.predict(X)
    if hasattr(model, "predict_proba"): result["malicious_probability"] = model.predict_proba(X)[:, 1]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True); result.to_csv(args.output, index=False)
    print(f"Saved {len(result)} predictions to {Path(args.output).resolve()}")
if __name__ == "__main__": main()
