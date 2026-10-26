"""Score new numeric network-flow rows with a saved NetSentry model.

Supports batch scoring, risk level assignment, threshold adjustments, and
integration with explainability narratives.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence
import joblib
import numpy as np
import pandas as pd


def score_flows(
    model: Any,
    expected_features: Sequence[str],
    frame: pd.DataFrame,
    threshold: float = 0.5,
) -> pd.DataFrame:
    """Score flow records and enrich with probabilities and risk classifications.

    Args:
        model: Fitted pipeline or estimator.
        expected_features: Ordered list of feature names.
        frame: Input DataFrame containing flow columns.
        threshold: Decision threshold for positive malicious class.

    Returns:
        DataFrame with predictions, scores, and risk tiers appended.
    """
    missing = [name for name in expected_features if name not in frame.columns]
    if missing:
        raise ValueError("Input is missing trained feature columns: " + ", ".join(missing))

    X = frame[list(expected_features)].apply(pd.to_numeric, errors="coerce")
    result = frame.copy()

    # Probability scoring if supported
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)
        if probs.ndim > 1 and probs.shape[1] >= 2:
            mal_prob = probs[:, 1]
            result["malicious_score"] = mal_prob.round(4)
            result["prediction"] = (mal_prob >= threshold).astype(int)
        else:
            result["prediction"] = model.predict(X)
    else:
        result["prediction"] = model.predict(X)

    # Assign risk tier
    if "malicious_score" in result.columns:
        scores = result["malicious_score"]
        conditions = [
            scores >= 0.85,
            scores >= 0.60,
            scores >= 0.40,
        ]
        choices = ["CRITICAL", "HIGH", "MEDIUM"]
        result["risk_level"] = np.select(conditions, choices, default="LOW")
    else:
        result["risk_level"] = np.where(result["prediction"] == 1, "HIGH", "LOW")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="artifacts/best_model.joblib", help="Path to saved model pipeline.")
    parser.add_argument("--features", default="artifacts/feature_names.json", help="Path to feature_names.json.")
    parser.add_argument("--data", required=True, help="Unlabeled CSV of flows to score.")
    parser.add_argument("--output", default="artifacts/predictions.csv", help="Destination path for scored CSV.")
    parser.add_argument("--threshold", type=float, default=0.5, help="Decision threshold for malicious class.")
    args = parser.parse_args()

    expected = json.loads(Path(args.features).read_text(encoding="utf-8"))
    frame = pd.read_csv(args.data, low_memory=False)
    frame.columns = [str(c).strip() for c in frame.columns]

    model = joblib.load(args.model)
    result = score_flows(model, expected, frame, threshold=args.threshold)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(out_path, index=False)

    flagged = int((result["prediction"] == 1).sum())
    print(f"[*] Scored {len(result)} flows: {flagged} flagged as malicious ({flagged / len(result) * 100:.1f}%)")
    print(f"[+] Saved predictions to {out_path.resolve()}")


if __name__ == "__main__":
    main()
