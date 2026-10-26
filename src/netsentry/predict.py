"""Score new numeric network-flow rows with a saved NetSentry model.

Supports batch scoring, risk level assignment, threshold adjustments, safe failure
for corrupted records, infinite value sanitization, and unsupervised anomaly scoring.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence
import joblib
import numpy as np
import pandas as pd


class PredictionError(Exception):
    """Base exception for inference pipeline failures."""
    pass


class SchemaMismatchError(PredictionError, ValueError):
    """Raised when input feature schema does not match model expectations."""
    pass


class EmptyInputError(PredictionError, ValueError):
    """Raised when input data has 0 records."""
    pass


def score_flows(
    model: Any,
    expected_features: Sequence[str],
    frame: pd.DataFrame,
    threshold: float = 0.5,
    max_corrupt_ratio: float = 0.8,
    quarantine_non_finite: bool = True,
) -> pd.DataFrame:
    """Score flow records and enrich with probabilities, risk tiers, and data quality status.

    Safety & Quarantine Policy:
        - CLEAN: All expected features are finite and present. Scored normally.
        - IMPUTED_VALID: Minor missingness (<= max_corrupt_ratio) without non-finite values.
          Imputed with training statistics and scored.
        - INVALID_NON_FINITE: Contains +inf or -inf (e.g. from 0-duration rate division).
          Unphysical measurements are quarantined (prediction=-1, risk_level='QUARANTINE_NON_FINITE')
          rather than silently imputed and presented as benign traffic.
        - CORRUPT_EXCESSIVE_MISSING: Severe missingness (> max_corrupt_ratio).
          Quarantined as UNPARSEABLE_ANOMALY.

    Args:
        model: Fitted pipeline or estimator.
        expected_features: Ordered list of feature names.
        frame: Input DataFrame containing flow columns.
        threshold: Decision threshold for positive malicious class.
        max_corrupt_ratio: Maximum proportion of missing/corrupt values allowed
            before a flow is flagged as UNPARSEABLE_ANOMALY.
        quarantine_non_finite: If True (default), flows containing +inf/-inf are quarantined
            with prediction=-1 rather than silently converted to median benign flows.

    Returns:
        DataFrame with predictions, scores, risk tiers, and data_status appended.
    """
    if not isinstance(frame, pd.DataFrame):
        raise TypeError(f"Expected pandas DataFrame for 'frame', got {type(frame).__name__}")

    result = frame.copy()

    # Handle empty input safely
    if len(frame) == 0:
        result["prediction"] = pd.Series(dtype=int)
        result["risk_level"] = pd.Series(dtype=str)
        result["malicious_score"] = pd.Series(dtype=float)
        result["data_status"] = pd.Series(dtype=str)
        return result

    # Check for missing expected features
    missing = [name for name in expected_features if name not in frame.columns]
    if missing:
        raise SchemaMismatchError("Input is missing trained feature columns: " + ", ".join(missing))

    # Convert numeric features
    X_raw = frame[list(expected_features)].apply(pd.to_numeric, errors="coerce")

    # Detect non-finite values (+inf, -inf) before replacement
    is_non_finite = np.isinf(X_raw).any(axis=1)

    # Convert infinities to NaN for statistical handling
    X = X_raw.replace([np.inf, -np.inf], np.nan)

    # Detect missingness ratio
    nan_ratio = X.isna().mean(axis=1)
    is_excessive_missing = nan_ratio > max_corrupt_ratio

    # Enforce Quarantine Safety Policy
    if quarantine_non_finite:
        quarantine_mask = is_non_finite | is_excessive_missing
    else:
        quarantine_mask = is_excessive_missing

    valid_mask = ~quarantine_mask

    # Assign structured data_status column
    data_status = pd.Series("CLEAN", index=result.index, dtype=object)
    mild_missing = (X.isna().any(axis=1)) & valid_mask
    data_status[mild_missing] = "IMPUTED_VALID"
    if is_non_finite.any():
        data_status[is_non_finite] = "INVALID_NON_FINITE" if quarantine_non_finite else "NON_FINITE_IMPUTED"
    if is_excessive_missing.any():
        data_status[is_excessive_missing] = "CORRUPT_EXCESSIVE_MISSING"

    result["data_status"] = data_status

    # Detect if model is an unsupervised anomaly detector (e.g. Isolation Forest)
    is_isolation_forest = False
    est = model
    if hasattr(model, "steps"):
        est = model.steps[-1][1]
    if "IsolationForest" in est.__class__.__name__:
        is_isolation_forest = True

    # Pre-allocate output columns
    result["prediction"] = 0
    result["risk_level"] = "LOW"

    if valid_mask.any():
        X_valid = X.loc[valid_mask]

        if is_isolation_forest:
            # Sklearn Isolation Forest convention: +1 = inlier (normal), -1 = outlier (anomaly)
            raw_preds = model.predict(X_valid)
            # Map: +1 -> 0 (Benign), -1 -> 1 (Anomaly)
            iso_preds = np.where(raw_preds == -1, 1, 0)
            result.loc[valid_mask, "prediction"] = iso_preds

            # Anomaly score from decision_function (negative for outliers)
            if hasattr(model, "decision_function"):
                raw_df = model.decision_function(X_valid)
                # Invert so higher score means higher anomaly magnitude
                result.loc[valid_mask, "anomaly_score"] = (-raw_df).round(4)

            # Assign risk level based on Isolation Forest anomaly decision
            result.loc[valid_mask, "risk_level"] = np.where(iso_preds == 1, "HIGH", "LOW")

        elif hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_valid)
            if probs.ndim > 1 and probs.shape[1] >= 2:
                mal_prob = probs[:, 1]
                # Validate finite probabilities
                if not np.isfinite(mal_prob).all():
                    raise PredictionError("Model predicted non-finite probability scores.")
                result.loc[valid_mask, "malicious_score"] = mal_prob.round(4)
                result.loc[valid_mask, "prediction"] = (mal_prob >= threshold).astype(int)

                # Assign risk tier based on threshold ranges
                scores = result.loc[valid_mask, "malicious_score"]
                conditions = [
                    scores >= 0.85,
                    scores >= 0.60,
                    scores >= 0.40,
                ]
                choices = ["CRITICAL", "HIGH", "MEDIUM"]
                result.loc[valid_mask, "risk_level"] = np.select(conditions, choices, default="LOW")
            else:
                preds = model.predict(X_valid)
                result.loc[valid_mask, "prediction"] = preds
                result.loc[valid_mask, "risk_level"] = np.where(preds == 1, "HIGH", "LOW")
        else:
            preds = model.predict(X_valid)
            result.loc[valid_mask, "prediction"] = preds
            result.loc[valid_mask, "risk_level"] = np.where(preds == 1, "HIGH", "LOW")

    # Safe failure isolation: flag quarantined rows rather than silently passing as benign
    if is_non_finite.any() and quarantine_non_finite:
        result.loc[is_non_finite, "prediction"] = -1
        result.loc[is_non_finite, "risk_level"] = "QUARANTINE_NON_FINITE"
        if "malicious_score" in result.columns:
            result.loc[is_non_finite, "malicious_score"] = np.nan
        if "anomaly_score" in result.columns:
            result.loc[is_non_finite, "anomaly_score"] = np.nan

    if is_excessive_missing.any():
        result.loc[is_excessive_missing, "prediction"] = -1
        result.loc[is_excessive_missing, "risk_level"] = "UNPARSEABLE_ANOMALY"
        if "malicious_score" in result.columns:
            result.loc[is_excessive_missing, "malicious_score"] = np.nan
        if "anomaly_score" in result.columns:
            result.loc[is_excessive_missing, "anomaly_score"] = np.nan

    return result



def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="artifacts/best_model.joblib", help="Path to saved model pipeline.")
    parser.add_argument("--features", default="artifacts/feature_names.json", help="Path to feature_names.json.")
    parser.add_argument("--data", required=True, help="Unlabeled CSV of flows to score.")
    parser.add_argument("--output", default="artifacts/predictions.csv", help="Destination path for scored CSV.")
    parser.add_argument("--threshold", type=float, default=0.5, help="Decision threshold for malicious class.")
    parser.add_argument("--max-rows", type=int, default=500000, help="Maximum flow rows to score in batch.")
    args = parser.parse_args()

    features_path = Path(args.features)
    if not features_path.is_file():
        raise FileNotFoundError(f"Feature schema file not found: {features_path}")
    expected = json.loads(features_path.read_text(encoding="utf-8"))

    data_path = Path(args.data)
    if not data_path.is_file():
        raise FileNotFoundError(f"Input data file not found: {data_path}")

    # File size safeguard (100 MB max for direct batch processing)
    file_size_mb = data_path.stat().st_size / (1024 * 1024)
    if file_size_mb > 100.0:
        raise ValueError(f"Input CSV exceeds maximum safe batch limit of 100 MB (file is {file_size_mb:.1f} MB).")

    frame = pd.read_csv(data_path, nrows=args.max_rows, low_memory=False)
    frame.columns = [str(c).strip() for c in frame.columns]

    model_path = Path(args.model)
    if not model_path.is_file():
        raise FileNotFoundError(f"Model artifact file not found: {model_path}")
    model = joblib.load(model_path)

    result = score_flows(model, expected, frame, threshold=args.threshold)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(out_path, index=False)

    flagged = int((result["prediction"] == 1).sum())
    corrupt = int((result["prediction"] == -1).sum())
    total = len(result)
    print(f"[*] Scored {total} flows: {flagged} flagged as malicious ({flagged / max(total, 1) * 100:.1f}%)")
    if corrupt > 0:
        print(f"[!] Warning: {corrupt} flows ({corrupt / max(total, 1) * 100:.1f}%) were unparseable and flagged as UNPARSEABLE_ANOMALY.")
    print(f"[+] Saved predictions to {out_path.resolve()}")


if __name__ == "__main__":
    main()

