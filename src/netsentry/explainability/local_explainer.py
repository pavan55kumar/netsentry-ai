"""Local instance attribution and single-flow inspection for NetSentry AI.

What it does:
    Inspects an individual network flow, decomposes its feature values relative to
    the normal benign baseline distribution, and highlights which flow characteristics
    pushed the model's decision toward benign or malicious.

Why it is needed:
    When a security firewall flags a connection, network administrators cannot simply
    trust a black-box probability score. They need concrete evidence: was it flagged
    because of a packet flood, an unacknowledged SYN flag, or an unusual payload size?

DCN / ML connection:
    Connects statistical outlier deviations (z-scores and feature attributions) to
    underlying networking phenomena (TCP handshakes, DoS rates, scan probing).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline


@dataclass
class LocalFlowExplanation:
    """Detailed attribution and baseline comparison for a single network flow."""
    flow_id: str | int
    predicted_label: int | str
    predicted_name: str
    confidence_score: float | None
    raw_values: dict[str, float]
    normal_medians: dict[str, float]
    deviations: dict[str, float]  # Feature -> signed z-score or normalized difference
    top_pushing_attack: list[dict[str, Any]] = field(default_factory=list)
    top_pushing_benign: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "predicted_name": self.predicted_name,
            "confidence_score": round(self.confidence_score, 4) if self.confidence_score is not None else None,
            "raw_values": {k: round(v, 3) for k, v in self.raw_values.items()},
            "normal_medians": {k: round(v, 3) for k, v in self.normal_medians.items()},
            "deviations": {k: round(v, 2) for k, v in self.deviations.items()},
            "top_pushing_attack": self.top_pushing_attack,
            "top_pushing_benign": self.top_pushing_benign,
        }


def explain_single_flow(
    pipeline: Pipeline,
    flow_row: pd.Series | pd.DataFrame,
    X_background: pd.DataFrame,
    target_names: list[str] | None = None,
    flow_id: str | int = "flow_0",
) -> LocalFlowExplanation:
    """Analyze a single flow record and calculate directional feature contributions.

    Args:
        pipeline: Fitted scikit-learn Pipeline.
        flow_row: Single row of features matching trained columns.
        X_background: Reference dataset representing baseline traffic (e.g. training set).
        target_names: Human-readable class names.
        flow_id: Identifier for the flow record.

    Returns:
        LocalFlowExplanation object.
    """
    if isinstance(flow_row, pd.Series):
        flow_df = pd.DataFrame([flow_row])
    else:
        flow_df = flow_row.iloc[:1]

    # Align columns
    features = list(X_background.columns)
    flow_clean = flow_df[features].apply(pd.to_numeric, errors="coerce")

    # Predict
    pred_idx = int(pipeline.predict(flow_clean)[0])
    prob: float | None = None
    if hasattr(pipeline, "predict_proba"):
        probs = pipeline.predict_proba(flow_clean)[0]
        prob = float(probs[pred_idx])

    if target_names and pred_idx < len(target_names):
        pred_name = target_names[pred_idx]
    else:
        pred_name = "Malicious" if pred_idx == 1 else "Benign"

    # Compute baseline statistics
    medians = X_background[features].median()
    stds = X_background[features].std().replace(0, 1.0).fillna(1.0)

    raw_dict = {f: float(flow_clean[f].iloc[0]) for f in features}
    median_dict = {f: float(medians[f]) for f in features}

    deviations = {}
    attack_pushers = []
    benign_pushers = []

    for f in features:
        val = raw_dict[f]
        med = median_dict[f]
        s = float(stds[f])
        z = (val - med) / s
        deviations[f] = float(z)

        diff_ratio = (val - med) / max(abs(med), 1.0)

        # Heuristic directional contribution
        item = {
            "feature": f,
            "observed": val,
            "normal_median": med,
            "z_score": round(float(z), 2),
            "diff_ratio": round(float(diff_ratio), 2),
        }

        # Elevated packet rates, byte rates, syn flags, duration anomalies often indicate attack
        if z > 1.0 or ("syn" in f.lower() and val > med) or ("packet" in f.lower() and val > med * 2):
            attack_pushers.append(item)
        elif abs(z) < 0.5:
            benign_pushers.append(item)

    # Sort attack pushers by highest positive z-score
    attack_pushers.sort(key=lambda x: x["z_score"], reverse=True)
    benign_pushers.sort(key=lambda x: abs(x["z_score"]))

    return LocalFlowExplanation(
        flow_id=flow_id,
        predicted_label=pred_idx,
        predicted_name=pred_name,
        confidence_score=prob,
        raw_values=raw_dict,
        normal_medians=median_dict,
        deviations=deviations,
        top_pushing_attack=attack_pushers[:4],
        top_pushing_benign=benign_pushers[:4],
    )
