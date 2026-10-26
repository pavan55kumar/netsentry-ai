"""Adversarial robustness, measurement noise, and distribution-shift research for NetSentry AI.

What it does:
    Evaluates ML intrusion detection models under controlled, physically defensible
    perturbations: sensor measurement noise, feature dropout/missingness, extreme
    valid network regimes (jumbo frames, 100G line rate, microsecond bursts),
    adversarial rate pacing, and benign composition shifts.

Why it is needed:
    Real-world network sensors suffer from timestamp jitter, hardware counter overflow,
    packet sampling, and packet drops. Adversaries intentionally pace malicious payloads
    (Slowloris, Low-and-Slow DoS) to mimic benign background noise. A model that achieves
    99% accuracy on clean test sets can collapse under minor real-world variations.

DCN / ML connection:
    - Measurement Jitter: Network interface cards (NICs) experience clock drift and
      polling latency, introducing +/- 5-15% variance in packet inter-arrival times and rates.
    - Physical Bounds: Traffic features must obey network constraints (e.g., packet sizes <= MTU,
      durations >= 0, integer packet counts). Arbitrary unbounded perturbations represent
      physically impossible traffic and yield misleading robustness evaluations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, confusion_matrix


@dataclass
class PerturbationResult:
    """Quantitative outcome of a specific perturbation or distribution shift test."""
    test_name: str
    category: str  # 'measurement_noise', 'missing_features', 'extreme_values', 'rate_pacing'
    description: str
    original_macro_f1: float
    perturbed_macro_f1: float
    f1_delta: float
    flip_rate_pct: float
    original_fpr: float
    perturbed_fpr: float
    fpr_delta: float
    mean_score_delta: float
    total_samples: int
    num_flipped: int
    status: str = "COMPLETED"  # 'COMPLETED', 'UNSUPPORTED'
    features_perturbed: list[str] = field(default_factory=list)
    transformation_verified: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_name": self.test_name,
            "category": self.category,
            "status": self.status,
            "description": self.description,
            "features_perturbed": self.features_perturbed,
            "transformation_verified": self.transformation_verified,
            "original_macro_f1": round(self.original_macro_f1, 4),
            "perturbed_macro_f1": round(self.perturbed_macro_f1, 4),
            "f1_delta": round(self.f1_delta, 4),
            "flip_rate_pct": round(self.flip_rate_pct, 2),
            "original_fpr": round(self.original_fpr, 4),
            "perturbed_fpr": round(self.perturbed_fpr, 4),
            "fpr_delta": round(self.fpr_delta, 4),
            "mean_score_delta": round(self.mean_score_delta, 4),
            "total_samples": self.total_samples,
            "num_flipped": self.num_flipped,
            "details": self.details,
        }


@dataclass
class RobustnessSuiteResult:
    """Comprehensive test harness result across all stress vectors."""
    timestamp: str
    model_name: str
    total_test_samples: int
    perturbation_results: list[PerturbationResult]
    resilience_score: float  # 0 to 100 aggregate resilience metric
    vulnerabilities_found: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "model_name": self.model_name,
            "total_test_samples": self.total_test_samples,
            "resilience_score": round(self.resilience_score, 1),
            "perturbation_results": [r.to_dict() for r in self.perturbation_results],
            "vulnerabilities_found": self.vulnerabilities_found,
            "recommendations": self.recommendations,
        }


def _calc_fpr_and_f1(y_true: np.ndarray, y_pred: np.ndarray) -> tuple[float, float]:
    """Calculate binary/macro F1 and False Positive Rate safely."""
    f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / max(fp + tn, 1))
    return f1, fpr


def _find_matching_columns(columns: list[str], keywords: list[str]) -> list[str]:
    """Find all column names matching any of the specified lowercase keywords."""
    matched = []
    for col in columns:
        c_lower = col.lower().strip()
        if any(kw in c_lower for kw in keywords):
            matched.append(col)
    return matched


def evaluate_single_perturbation(
    pipeline: Any,
    X_orig: pd.DataFrame,
    X_perturbed: pd.DataFrame,
    y_true: pd.Series,
    test_name: str,
    category: str,
    description: str,
    features_perturbed: list[str] | None = None,
) -> PerturbationResult:
    """Compare baseline pipeline performance against perturbed input traffic."""
    # Check if any features were actually modified
    pert_cols = features_perturbed if features_perturbed is not None else list(X_orig.columns)
    if not pert_cols:
        # Schema does not support this perturbation
        return PerturbationResult(
            test_name=test_name,
            category=category,
            description=f"{description} (UNSUPPORTED: Target features not present in dataset schema)",
            original_macro_f1=0.0,
            perturbed_macro_f1=0.0,
            f1_delta=0.0,
            flip_rate_pct=0.0,
            original_fpr=0.0,
            perturbed_fpr=0.0,
            fpr_delta=0.0,
            mean_score_delta=0.0,
            total_samples=len(y_true),
            num_flipped=0,
            status="UNSUPPORTED",
            features_perturbed=[],
            transformation_verified=False,
            details={"unsupported_reason": "No matching feature columns found in dataset schema."},
        )

    # Baseline predictions
    y_true_arr = y_true.to_numpy()
    orig_preds = pipeline.predict(X_orig)
    orig_f1, orig_fpr = _calc_fpr_and_f1(y_true_arr, orig_preds)

    # Verify that input features actually changed
    is_changed = not X_perturbed[pert_cols].equals(X_orig[pert_cols])

    # Perturbed predictions
    pert_preds = pipeline.predict(X_perturbed)
    pert_f1, pert_fpr = _calc_fpr_and_f1(y_true_arr, pert_preds)


    # Flip statistics
    flips = (orig_preds != pert_preds)
    num_flipped = int(flips.sum())
    flip_rate = (num_flipped / len(orig_preds)) * 100.0

    # Malicious score shift if probability scoring supported
    mean_score_delta = 0.0
    if hasattr(pipeline, "predict_proba"):
        orig_probs = pipeline.predict_proba(X_orig)[:, 1]
        pert_probs = pipeline.predict_proba(X_perturbed)[:, 1]
        mean_score_delta = float(np.mean(np.abs(pert_probs - orig_probs)))

    f1_delta = pert_f1 - orig_f1
    fpr_delta = pert_fpr - orig_fpr

    return PerturbationResult(
        test_name=test_name,
        category=category,
        description=description,
        original_macro_f1=orig_f1,
        perturbed_macro_f1=pert_f1,
        f1_delta=f1_delta,
        flip_rate_pct=flip_rate,
        original_fpr=orig_fpr,
        perturbed_fpr=pert_fpr,
        fpr_delta=fpr_delta,
        mean_score_delta=mean_score_delta,
        total_samples=len(y_true),
        num_flipped=num_flipped,
        status="COMPLETED",
        features_perturbed=pert_cols,
        transformation_verified=is_changed,
        details={
            "malicious_to_benign_flips": int(((orig_preds == 1) & (pert_preds == 0)).sum()),
            "benign_to_malicious_flips": int(((orig_preds == 0) & (pert_preds == 1)).sum()),
        },
    )


def apply_gaussian_measurement_noise(
    X: pd.DataFrame, noise_pct: float = 0.05, random_state: int = 42
) -> tuple[pd.DataFrame, list[str]]:
    """Add zero-mean Gaussian jitter to continuous features obeying physical positivity."""
    rng = np.random.default_rng(random_state)
    X_pert = X.copy()
    numeric_cols = list(X.select_dtypes(include=[np.number]).columns)
    modified_cols = []

    for col in numeric_cols:
        # Do not add continuous noise to discrete TCP flag counts
        if "flag" in col.lower() or "count" in col.lower() or "port" in col.lower():
            continue
        vals = X[col].to_numpy(dtype=float)
        std = np.nanstd(vals)
        if std == 0 or np.isnan(std):
            std = max(np.nanmean(vals) * 0.1, 1.0)
        noise = rng.normal(0, std * noise_pct, size=len(vals))
        new_vals = np.maximum(vals + noise, 0.0)
        X_pert[col] = new_vals
        modified_cols.append(col)

    return X_pert, modified_cols


def apply_missing_feature_injection(
    X: pd.DataFrame, missing_ratio: float = 0.10, random_state: int = 42
) -> tuple[pd.DataFrame, list[str]]:
    """Randomly inject NaN missing values across feature matrix to test imputation resilience."""
    rng = np.random.default_rng(random_state)
    X_pert = X.copy()
    numeric_cols = list(X.select_dtypes(include=[np.number]).columns)

    for col in numeric_cols:
        mask = rng.uniform(0, 1, size=len(X)) < missing_ratio
        X_pert.loc[mask, col] = np.nan

    return X_pert, numeric_cols


def apply_extreme_valid_stress(X: pd.DataFrame, stress_type: str) -> tuple[pd.DataFrame, list[str]]:
    """Inject physically plausible extreme edge cases supporting multiple benchmark schemas."""
    X_pert = X.copy()
    modified_cols = []
    all_cols = list(X_pert.columns)

    if stress_type == "jumbo_frames":
        # Data center 9000-byte MTU jumbo frame traffic
        size_cols = _find_matching_columns(all_cols, [
            "average packet size", "packet length mean", "max packet length",
            "fwd packet length max", "bwd packet length max", "avg fwd segment size",
            "avg bwd segment size", "average_packet_size", "smean", "dmean",
        ])
        for col in size_cols:
            X_pert[col] = 8960.0
            modified_cols.append(col)

        # Scale byte rates corresponding to 6x packet size increase
        byte_rate_cols = _find_matching_columns(all_cols, ["flow bytes/s", "flow_bytes_per_second"])
        for col in byte_rate_cols:
            X_pert[col] = X_pert[col] * 6.0
            modified_cols.append(col)

    elif stress_type == "line_rate_100g":
        # 100 Gbps line-rate burst ($1.25e10 B/s)
        byte_cols = _find_matching_columns(all_cols, ["flow bytes/s", "flow_bytes_per_second"])
        for col in byte_cols:
            X_pert[col] = 1.25e10
            modified_cols.append(col)

        pkt_cols = _find_matching_columns(all_cols, ["flow packets/s", "flow_packets_per_second", "fwd packets/s", "bwd packets/s"])
        for col in pkt_cols:
            X_pert[col] = 1.48e7
            modified_cols.append(col)

    elif stress_type == "microsecond_burst":
        dur_cols = _find_matching_columns(all_cols, ["flow duration", "flow_duration_ms", "dur"])
        for col in dur_cols:
            X_pert[col] = 5.0  # 5 microseconds in CIC or 0.005 ms in demo
            modified_cols.append(col)

        fwd_cols = _find_matching_columns(all_cols, ["total fwd packets", "total_fwd_packets", "spkts"])
        for col in fwd_cols:
            X_pert[col] = 1
            modified_cols.append(col)

    return X_pert, modified_cols


def apply_adversarial_pacing(X: pd.DataFrame, pace_factor: float = 10.0) -> tuple[pd.DataFrame, list[str]]:
    """Simulate Slowloris / low-and-slow rate attenuation evasion across schemas."""
    X_pert = X.copy()
    modified_cols = []
    all_cols = list(X_pert.columns)

    # Dilate flow duration (pacing packets over longer time interval)
    dur_cols = _find_matching_columns(all_cols, ["flow duration", "flow_duration_ms", "dur"])
    for col in dur_cols:
        X_pert[col] = X_pert[col] * pace_factor
        modified_cols.append(col)

    # Attenuate packet transmission rates
    pkt_rate_cols = _find_matching_columns(all_cols, ["flow packets/s", "flow_packets_per_second", "fwd packets/s", "bwd packets/s"])
    for col in pkt_rate_cols:
        X_pert[col] = np.maximum(X_pert[col] / pace_factor, 0.01)
        modified_cols.append(col)

    # Attenuate byte transmission rates
    byte_rate_cols = _find_matching_columns(all_cols, ["flow bytes/s", "flow_bytes_per_second"])
    for col in byte_rate_cols:
        X_pert[col] = np.maximum(X_pert[col] / pace_factor, 0.1)
        modified_cols.append(col)

    return X_pert, modified_cols


def run_robustness_evaluation_suite(
    pipeline: Any,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    model_name: str = "Trained Champion",
) -> RobustnessSuiteResult:
    """Execute complete battery of adversarial perturbation and distribution-shift experiments."""
    results: list[PerturbationResult] = []

    # 1. Measurement Noise (5% NIC jitter)
    X_noise_5, cols_noise_5 = apply_gaussian_measurement_noise(X_test, noise_pct=0.05, random_state=42)
    res_noise_5 = evaluate_single_perturbation(
        pipeline, X_test, X_noise_5, y_test,
        test_name="Measurement Jitter (5%)",
        category="measurement_noise",
        description="Simulates +/- 5% hardware NIC timestamp and counter clock drift.",
        features_perturbed=cols_noise_5,
    )
    results.append(res_noise_5)

    # 2. Measurement Noise (15% High Jitter)
    X_noise_15, cols_noise_15 = apply_gaussian_measurement_noise(X_test, noise_pct=0.15, random_state=42)
    res_noise_15 = evaluate_single_perturbation(
        pipeline, X_test, X_noise_15, y_test,
        test_name="High Measurement Jitter (15%)",
        category="measurement_noise",
        description="Simulates extreme +/- 15% packet delay variation across congested switches.",
        features_perturbed=cols_noise_15,
    )
    results.append(res_noise_15)

    # 3. Missing Feature Dropout (10%)
    X_drop_10, cols_drop_10 = apply_missing_feature_injection(X_test, missing_ratio=0.10, random_state=42)
    res_drop_10 = evaluate_single_perturbation(
        pipeline, X_test, X_drop_10, y_test,
        test_name="Feature Dropout (10% Missing)",
        category="missing_features",
        description="Simulates 10% random telemetry loss from sampled NetFlow/sFlow sensors.",
        features_perturbed=cols_drop_10,
    )
    results.append(res_drop_10)

    # 4. Missing Feature Dropout (25%)
    X_drop_25, cols_drop_25 = apply_missing_feature_injection(X_test, missing_ratio=0.25, random_state=42)
    res_drop_25 = evaluate_single_perturbation(
        pipeline, X_test, X_drop_25, y_test,
        test_name="Severe Feature Dropout (25% Missing)",
        category="missing_features",
        description="Simulates 25% sensor packet drop or unpopulated flow meter fields.",
        features_perturbed=cols_drop_25,
    )
    results.append(res_drop_25)

    # 5. Extreme Physical Traffic: Jumbo Frames (MTU 9000)
    X_jumbo, cols_jumbo = apply_extreme_valid_stress(X_test, "jumbo_frames")
    res_jumbo = evaluate_single_perturbation(
        pipeline, X_test, X_jumbo, y_test,
        test_name="Enterprise Jumbo Frames (MTU 9000)",
        category="extreme_values",
        description="Examines model behavior when encountering storage-network 9KB frames.",
        features_perturbed=cols_jumbo,
    )
    results.append(res_jumbo)

    # 6. Extreme Physical Traffic: Line-Rate 100 Gbps Burst
    X_100g, cols_100g = apply_extreme_valid_stress(X_test, "line_rate_100g")
    res_100g = evaluate_single_perturbation(
        pipeline, X_test, X_100g, y_test,
        test_name="100 Gbps Line-Rate Burst",
        category="extreme_values",
        description="Tests numerical stability under 12.5 GB/s wire-speed bursts.",
        features_perturbed=cols_100g,
    )
    results.append(res_100g)

    # 7. Adversarial Low-and-Slow Rate Pacing (Slowloris evasion)
    X_pacing, cols_pacing = apply_adversarial_pacing(X_test, pace_factor=10.0)
    res_pacing = evaluate_single_perturbation(
        pipeline, X_test, X_pacing, y_test,
        test_name="Adversarial Low-and-Slow Pacing",
        category="rate_pacing",
        description="Adversary artificially dilates flow duration 10x to suppress packet rate.",
        features_perturbed=cols_pacing,
    )
    results.append(res_pacing)

    # Synthesis & Vulnerability Diagnosis
    vulnerabilities = []
    recommendations = []

    # Check for severe F1 drop among completed tests
    completed = [r for r in results if r.status == "COMPLETED"]
    max_f1_drop = max([abs(r.f1_delta) for r in completed if r.f1_delta < 0] + [0.0])
    if max_f1_drop > 0.10:
        vulnerabilities.append(f"Model exhibits severe performance degradation under stress (max Macro-F1 drop: {max_f1_drop:.3f}).")
        recommendations.append("Incorporate perturbed training samples (noise augmentation) during pipeline fitting.")

    # Check for high flip rate under small noise
    if res_noise_5.flip_rate_pct > 5.0:
        vulnerabilities.append(f"Model is brittle to 5% measurement noise ({res_noise_5.flip_rate_pct:.1f}% predictions flipped).")
        recommendations.append("Apply regularization or feature discretization to reduce sensitivity to small numerical fluctuations.")

    # Check for adversarial pacing evasion
    pacing_mal_to_ben = res_pacing.details.get("malicious_to_benign_flips", 0)
    if pacing_mal_to_ben > 0:
        vulnerabilities.append(f"Adversarial rate pacing enabled {pacing_mal_to_ben} attacks to evade detection by lowering transmission rates.")
        recommendations.append("Do not rely solely on volumetric rate features; combine with TCP flag ratios and payload state metrics.")

    # Check for jumbo frame false positives
    jumbo_ben_to_mal = res_jumbo.details.get("benign_to_malicious_flips", 0)
    if jumbo_ben_to_mal > 0:
        vulnerabilities.append(f"Enterprise Jumbo Frames triggered {jumbo_ben_to_mal} false positive alerts on benign large-packet traffic.")
        recommendations.append("Calibrate packet size bounds for enterprise storage networks utilizing MTU 9000.")

    # Compute aggregate resilience score (100 - weighted degradation)
    avg_flip = float(np.mean([r.flip_rate_pct for r in completed])) if completed else 0.0
    resilience_score = max(0.0, min(100.0, 100.0 - (avg_flip * 1.5) - (max_f1_drop * 100.0)))

    if not vulnerabilities:
        vulnerabilities.append("No critical vulnerabilities detected under standard perturbation regimes.")

    return RobustnessSuiteResult(
        timestamp=datetime.now(timezone.utc).isoformat(),
        model_name=model_name,
        total_test_samples=len(y_test),
        perturbation_results=results,
        resilience_score=resilience_score,
        vulnerabilities_found=vulnerabilities,
        recommendations=recommendations,
    )

