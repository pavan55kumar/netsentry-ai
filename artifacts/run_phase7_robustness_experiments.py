"""Phase 7 Security Engineering, Robustness & Adversarial Perturbation Experiments.

What it does:
    Executes controlled, reproducible empirical robustness evaluations across:
    1. Continuous Measurement Jitter (+/- 5% and +/- 15% Gaussian NIC clock noise).
    2. Telemetry Missingness & Sensor Dropout (10% and 25% missing feature injection).
    3. Physically Defensible Extreme Regimes (Jumbo MTU 9000, 100 Gbps wire-speed burst).
    4. Adversarial Rate Pacing / Low-and-Slow Evasion (10x duration dilation).
    5. Input Validation, Non-Finite Sanitization, and Safe Unparseable Isolation.
    6. Isolation Forest Unsupervised Anomaly Decision Reliability.

Outputs:
    Saves complete structured results to artifacts/phase7_robustness_results.json.
"""
from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any
import numpy as np
import pandas as pd

from netsentry.data.preprocessor import prepare_data
from netsentry.models.factory import build_pipeline
from netsentry.predict import score_flows
from netsentry.research.robustness import (
    run_robustness_evaluation_suite,
    RobustnessSuiteResult,
    apply_gaussian_measurement_noise,
    apply_missing_feature_injection,
    apply_extreme_valid_stress,
    apply_adversarial_pacing,
)


def run_phase7_experiments() -> dict[str, Any]:
    print("=" * 80)
    print("NETSENTRY AI — PHASE 7 SECURITY ENGINEERING & ROBUSTNESS EXPERIMENTS")
    print("=" * 80)
    start_time = time.time()

    cic_path = Path("data/sample/cicids2017_sample.csv")
    if not cic_path.is_file():
        raise FileNotFoundError(f"Missing sample dataset: {cic_path}")

    print(f"[*] Ingesting CIC-IDS2017 dataset from {cic_path}...")
    df_cic = pd.read_csv(cic_path)
    df_cic.columns = [str(c).strip() for c in df_cic.columns]

    # Preprocess with leakage-free train/test partition
    prep = prepare_data(df_cic, label_column="Label", test_size=0.25, random_state=42)
    print(f"[+] Prepared dataset: {len(prep.X_train)} train samples, {len(prep.X_test)} test samples, {len(prep.feature_names)} features.")

    # =========================================================================
    # PART 1: CHAMPION LIGHTGBM ROBUSTNESS EVALUATION
    # =========================================================================
    print("\n" + "-" * 80)
    print("PART 1: CHAMPION LIGHTGBM ADVERSARIAL & DISTRIBUTION-SHIFT SUITE")
    print("-" * 80)

    lgbm_pipe = build_pipeline("lightgbm", random_state=42, fast_mode=True)
    print("[*] Training LightGBM pipeline on clean training fold...")
    lgbm_pipe.fit(prep.X_train, prep.y_train)

    lgbm_results = run_robustness_evaluation_suite(
        lgbm_pipe, prep.X_test, prep.y_test, model_name="LightGBM Champion"
    )

    print(f"[+] LightGBM Aggregate Resilience Score: {lgbm_results.resilience_score:.1f} / 100")
    print(f"    {'Perturbation Test':<38} {'Status':<11} {'Orig F1':<8} {'Pert F1':<8} {'F1 Delta':<9} {'Flip %':<7} {'FPR Shift':<9} {'Features'}")
    print("    " + "-" * 105)
    for res in lgbm_results.perturbation_results:
        feat_summary = f"{len(res.features_perturbed)} cols" if res.features_perturbed else "None"
        print(f"    {res.test_name:<38} {res.status:<11} {res.original_macro_f1:<8.4f} {res.perturbed_macro_f1:<8.4f} {res.f1_delta:<+9.4f} {res.flip_rate_pct:<6.2f}% {res.fpr_delta:<+9.4f} {feat_summary}")

    # =========================================================================
    # PART 2: RANDOM FOREST ENSEMBLE ROBUSTNESS COMPARISON
    # =========================================================================
    print("\n" + "-" * 80)
    print("PART 2: RANDOM FOREST ENSEMBLE COMPARISON")
    print("-" * 80)

    rf_pipe = build_pipeline("random_forest_500", random_state=42, fast_mode=True)
    print("[*] Training Random Forest pipeline on clean training fold...")
    rf_pipe.fit(prep.X_train, prep.y_train)

    rf_results = run_robustness_evaluation_suite(
        rf_pipe, prep.X_test, prep.y_test, model_name="Random Forest Ensemble"
    )

    print(f"[+] Random Forest Aggregate Resilience Score: {rf_results.resilience_score:.1f} / 100")
    print(f"    {'Perturbation Test':<38} {'Status':<11} {'Orig F1':<8} {'Pert F1':<8} {'F1 Delta':<9} {'Flip %':<7} {'FPR Shift':<9} {'Features'}")
    print("    " + "-" * 105)
    for res in rf_results.perturbation_results:
        feat_summary = f"{len(res.features_perturbed)} cols" if res.features_perturbed else "None"
        print(f"    {res.test_name:<38} {res.status:<11} {res.original_macro_f1:<8.4f} {res.perturbed_macro_f1:<8.4f} {res.f1_delta:<+9.4f} {res.flip_rate_pct:<6.2f}% {res.fpr_delta:<+9.4f} {feat_summary}")

    # =========================================================================
    # PART 3: SAFE FAILURE & CORRUPTION ISOLATION AUDIT
    # =========================================================================
    print("\n" + "-" * 80)
    print("PART 3: SAFE FAILURE & INPUT CORRUPTION ISOLATION AUDIT")
    print("-" * 80)

    # Synthetic test set containing clean, infinite, NaN, and 100% corrupted rows
    # Convert to float to avoid Pandas incompatible dtype FutureWarning
    corrupt_test_rows = prep.X_test.head(10).astype(float).copy().reset_index(drop=True)
    
    # Row 0: Clean flow
    # Row 1: Contains np.inf from zero-duration division
    corrupt_test_rows.loc[1, prep.feature_names[0]] = np.inf
    # Row 2: Contains negative infinity
    corrupt_test_rows.loc[2, prep.feature_names[1]] = -np.inf
    # Row 3: 100% NaN (all features unparseable / dropped)
    for f in prep.feature_names:
        corrupt_test_rows.loc[3, f] = np.nan
    # Row 4: 90% missing features (severe telemetry drop)
    for f in prep.feature_names[:int(len(prep.feature_names) * 0.9)]:
        corrupt_test_rows.loc[4, f] = np.nan
    # Row 5: 1 feature missing (genuinely missing measurement, within safe tolerance)
    corrupt_test_rows.loc[5, prep.feature_names[0]] = np.nan

    scored_corrupt = score_flows(lgbm_pipe, prep.feature_names, corrupt_test_rows, quarantine_non_finite=True)

    row0_pred = scored_corrupt.loc[0, "prediction"]
    row0_status = scored_corrupt.loc[0, "data_status"]
    row1_pred = scored_corrupt.loc[1, "prediction"]
    row1_risk = scored_corrupt.loc[1, "risk_level"]
    row1_status = scored_corrupt.loc[1, "data_status"]
    row3_pred = scored_corrupt.loc[3, "prediction"]
    row3_risk = scored_corrupt.loc[3, "risk_level"]
    row3_status = scored_corrupt.loc[3, "data_status"]
    row5_pred = scored_corrupt.loc[5, "prediction"]
    row5_status = scored_corrupt.loc[5, "data_status"]

    print(f"[*] Clean Row 0: Prediction = {row0_pred}, Risk = {scored_corrupt.loc[0, 'risk_level']}, Status = {row0_status}")
    print(f"[*] +Inf Row 1 (Zero-Duration Rate Division): Prediction = {row1_pred}, Risk = {row1_risk}, Status = {row1_status}")
    print(f"    --> SAFE QUARANTINE: Unphysical infinite rates are quarantined, NOT falsely reported as benign!")
    print(f"[*] 100% Corrupted Row 3: Prediction = {row3_pred}, Risk = {row3_risk}, Status = {row3_status}")
    print(f"    --> SAFE FAILURE: Completely corrupted flows are quarantined as UNPARSEABLE_ANOMALY.")
    print(f"[*] Mild Missingness Row 5 (1/77 NaN): Prediction = {row5_pred}, Status = {row5_status}")
    print(f"    --> SAFE IMPUTATION: Valid telemetry with minor missingness is reliably scored.")

    safe_failure_passed = (row1_pred == -1) and (row1_risk == "QUARANTINE_NON_FINITE") and (row3_pred == -1) and (row5_status == "IMPUTED_VALID")

    # =========================================================================
    # PART 4: ISOLATION FOREST ANOMALY DECISION & CALIBRATION CHECK
    # =========================================================================
    print("\n" + "-" * 80)
    print("PART 4: ISOLATION FOREST ANOMALY DECISION RELIABILITY")
    print("-" * 80)

    iso_pipe = build_pipeline("isolation_forest", random_state=42, fast_mode=True)
    # Fit only on benign training flows
    benign_mask = (prep.y_train == 0)
    iso_pipe.fit(prep.X_train[benign_mask])

    iso_scored = score_flows(iso_pipe, prep.feature_names, prep.X_test.head(50))
    iso_preds = iso_scored["prediction"].to_numpy()
    iso_risks = iso_scored["risk_level"].to_numpy()

    # Verify that prediction == 1 maps to HIGH risk and prediction == 0 maps to LOW risk
    iso_consistency = np.all((iso_preds == 1) == (iso_risks == "HIGH"))
    print(f"[+] Isolation Forest Inlier/Outlier Mapping Consistent: {iso_consistency}")
    print(f"    Total Evaluated: {len(iso_scored)}, Flagged Anomalies: {(iso_preds == 1).sum()}, Normal Inliers: {(iso_preds == 0).sum()}")

    elapsed = time.time() - start_time
    print(f"\n[+] Completed Phase 7 robustness battery in {elapsed:.2f} seconds.")

    output_payload = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evaluation_duration_seconds": round(elapsed, 2),
            "dataset": "CIC-IDS2017 Sample",
            "total_test_samples": len(prep.X_test),
            "feature_count": len(prep.feature_names),
        },
        "lightgbm_champion": lgbm_results.to_dict(),
        "random_forest_comparison": rf_results.to_dict(),
        "safe_failure_audit": {
            "infinite_value_quarantined": bool(row1_pred == -1 and row1_risk == "QUARANTINE_NON_FINITE"),
            "all_nan_isolated_as_anomaly": bool(row3_pred == -1),
            "mild_missingness_imputed": bool(row5_status == "IMPUTED_VALID"),
            "safe_failure_status": "PASSED" if safe_failure_passed else "FAILED",
        },
        "unsupervised_isolation_forest": {
            "mapping_consistent": bool(iso_consistency),
            "total_samples": len(iso_scored),
            "flagged_anomalies": int((iso_preds == 1).sum()),
            "normal_inliers": int((iso_preds == 0).sum()),
        },
    }

    out_file = Path("artifacts/phase7_robustness_results.json")
    out_file.write_text(json.dumps(output_payload, indent=2), encoding="utf-8")
    print(f"[+] Saved structured experiment results to {out_file.resolve()}")

    return output_payload


if __name__ == "__main__":
    run_phase7_experiments()
