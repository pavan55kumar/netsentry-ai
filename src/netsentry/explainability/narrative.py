"""Plain-English security analyst narrative generation for NetSentry AI.

What it does:
    Translates mathematical model outputs, feature attributions, and flow statistics
    into clear, jargon-free security incident explanations suitable for SOC analysts.

Why it is needed:
    A probability score alone (e.g. 0.87) is not actionable. Security teams require
    an honest, plain-English summary detailing which specific flow behaviors triggered
    the alert, accompanied by scientific caveats regarding correlation vs causation.

DCN / ML connection:
    Explains the networking mechanics behind the alert (e.g. half-open SYN handshakes,
    asymmetric forward/backward packet counts, or packet flood spikes).
"""
from __future__ import annotations

from typing import Any
from .local_explainer import LocalFlowExplanation


def generate_security_narrative(
    explanation: LocalFlowExplanation,
    is_calibrated: bool = False,
) -> dict[str, Any]:
    """Generate an honest, plain-English security explanation for a scored flow.

    Args:
        explanation: LocalFlowExplanation containing observed features and deviations.
        is_calibrated: True only if Platt scaling or isotonic calibration was evaluated.

    Returns:
        Dictionary containing summary, findings, technical breakdown, and limitations.
    """
    is_quarantined = explanation.predicted_label == -1 or explanation.predicted_name in {"QUARANTINE_NON_FINITE", "UNPARSEABLE_ANOMALY"}
    is_malicious = (not is_quarantined) and explanation.predicted_name.lower() not in {"benign", "normal", "0"}
    conf = explanation.confidence_score

    # Probability calibration honesty
    score_desc = (
        "QUARANTINED (Model prediction safely suppressed)"
        if is_quarantined
        else f"calibrated probability of {conf * 100:.1f}%"
        if is_calibrated and conf is not None
        else f"uncalibrated model score of {conf * 100:.1f}%"
        if conf is not None
        else "binary classification"
    )

    if is_quarantined:
        summary = (
            f"Flow [{explanation.flow_id}] was placed into structured QUARANTINE ({explanation.predicted_name}). "
            f"The connection features contain unphysical non-finite values (such as +/- Inf from zero-duration rate calculations) "
            f"or excessive missing telemetry (>80%). Under NetSentry AI Safe Failure Policy, automated classification was safely "
            f"suppressed to eliminate the silent benign failure vulnerability."
        )
        recommendation = (
            "Quarantine connection. Conduct manual SOC forensic analysis on endpoint telemetry and verify flow meter exporter health."
        )
    elif not is_malicious:
        summary = (
            f"Flow [{explanation.flow_id}] was classified as {explanation.predicted_name.upper()} "
            f"with an {score_desc}. All observed connection metrics fall within "
            f"expected baseline statistical distributions."
        )
        recommendation = "No security analyst action required. Traffic consistent with normal network operations."
    else:
        # Malicious flow
        pushers = explanation.top_pushing_attack
        if pushers:
            key_reasons = []
            for p in pushers[:3]:
                feat = p["feature"].replace("_", " ")
                obs = p["observed"]
                med = p["normal_median"]
                z = p["z_score"]
                if z > 2.0:
                    key_reasons.append(f"severely elevated {feat} ({obs:,.1f} vs normal median {med:,.1f}, +{z:.1f}σ)")
                elif "syn" in feat and obs > med:
                    key_reasons.append(f"unusual SYN flag count ({obs} vs normal {med})")
                elif "packet" in feat and obs > med:
                    key_reasons.append(f"elevated packet activity ({obs:,.1f} vs normal {med:,.1f})")
                else:
                    key_reasons.append(f"unusual {feat} ({obs:,.1f} vs normal {med:,.1f})")

            reasons_str = "; ".join(key_reasons)
            summary = (
                f"The model flagged flow [{explanation.flow_id}] as {explanation.predicted_name.upper()} "
                f"({score_desc}) because its observed characteristics differ significantly "
                f"from patterns associated with the normal class in the training data: {reasons_str}."
            )
        else:
            summary = (
                f"The model flagged flow [{explanation.flow_id}] as {explanation.predicted_name.upper()} "
                f"({score_desc}) due to multi-feature anomaly patterns across connection metrics."
            )

        recommendation = (
            "Verify whether this IP session represents a legitimate high-throughput transfer "
            "(e.g. backup or speedtest) or genuine malicious probing/flooding before blocking."
        )

    caveats = [
        "Feature Correlation vs Causation: The model identifies statistical correlations present in training data, which does not prove malicious intent.",
        "Operational Threshold: This decision was made at the active threshold. Adjust threshold in the Evaluation Center to control false alarms.",
        "Domain Generalization: Performance on this flow assumes the network environment matches the training feature distribution.",
    ]

    return {
        "verdict": explanation.predicted_name.upper(),
        "score_description": score_desc,
        "summary": summary,
        "actionable_recommendation": recommendation,
        "top_contributing_evidence": explanation.top_pushing_attack if is_malicious else explanation.top_pushing_benign,
        "scientific_limitations": caveats,
    }
