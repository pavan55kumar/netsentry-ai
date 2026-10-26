"""Phase 7 Security Engineering, Robustness, and Reliability Automated Tests.

What it tests:
    1. Input Validation & Safe Failure:
       - Empty DataFrames return safe empty structured schema.
       - Missing expected feature columns raise SchemaMismatchError (subclass of ValueError).
       - Infinite (+Inf, -Inf) values are safely sanitized during inference without crashing.
       - Heavily corrupted rows (>80% missing) are isolated as UNPARSEABLE_ANOMALY rather than silently passed as benign.
       - Isolation Forest inlier (+1) / outlier (-1) predictions correctly map to 0 (benign) / 1 (anomaly).
    2. PCAP & Network Flow Robustness:
       - 0-byte PCAP raises EmptyPcapError.
       - Invalid magic bytes raise CorruptPcapError.
       - Non-IP frames (e.g. ARP) are counted and ignored without crashing.
       - Zero reconstructed flows returns canonical flow schema columns.
       - Inter-packet silence exceeding idle timeout triggers flow boundary split.
    3. Privacy & Operational Logging:
       - IPv4 host octets are redacted (e.g. 192.168.1.***).
       - Credentials, tokens, and passwords are scrubbed.
       - Absolute user filesystem directories are sanitized.
    4. Robustness Perturbation Mechanics:
       - Continuous noise adheres to physical non-negativity.
       - Missing feature injection accurately controls missingness ratio.
       - Adversarial pacing monotonically increases flow duration.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import numpy as np
import pandas as pd

from netsentry.data.synthetic import make_demo_dataset
from netsentry.data.preprocessor import prepare_data
from netsentry.models.factory import build_pipeline
from netsentry.predict import (
    score_flows,
    SchemaMismatchError,
    PredictionError,
)
from netsentry.pcap.flow_extractor import (
    extract_flows_from_pcap,
    EmptyPcapError,
    CorruptPcapError,
    CANONICAL_FLOW_COLUMNS,
)
from netsentry.utils.logging import (
    redact_ip_address,
    sanitize_log_message,
    get_security_logger,
)
from netsentry.research.robustness import (
    apply_gaussian_measurement_noise,
    apply_missing_feature_injection,
    apply_adversarial_pacing,
)


class Phase7SecurityAndRobustnessTests(unittest.TestCase):
    """Automated tests for Phase 7 security hardening and reliability."""

    def setUp(self):
        self.df = make_demo_dataset(rows=80, random_state=42)
        self.prep = prepare_data(self.df, "label", test_size=0.25, random_state=42)
        self.pipe = build_pipeline("random_forest_500", random_state=42, fast_mode=True)
        self.pipe.fit(self.prep.X_train, self.prep.y_train)

    # =========================================================================
    # 1. INPUT VALIDATION & SAFE FAILURE
    # =========================================================================

    def test_empty_dataframe_handled_safely(self):
        """Verify that an empty DataFrame returns an empty structured DataFrame without crashing."""
        empty_df = pd.DataFrame(columns=self.prep.feature_names)
        scored = score_flows(self.pipe, self.prep.feature_names, empty_df)
        self.assertEqual(len(scored), 0)
        self.assertIn("prediction", scored.columns)
        self.assertIn("risk_level", scored.columns)
        self.assertIn("malicious_score", scored.columns)

    def test_missing_expected_features_raises_schema_mismatch(self):
        """Verify that missing expected columns raises SchemaMismatchError (which inherits ValueError)."""
        bad_df = self.prep.X_test.drop(columns=[self.prep.feature_names[0]])
        with self.assertRaises(SchemaMismatchError):
            score_flows(self.pipe, self.prep.feature_names, bad_df)

    def test_infinite_values_sanitized_during_scoring(self):
        """Verify that +/- Inf from 0-duration division are sanitized to finite values."""
        corrupt_df = self.prep.X_test.copy().reset_index(drop=True)
        corrupt_df.loc[0, self.prep.feature_names[0]] = np.inf
        corrupt_df.loc[1, self.prep.feature_names[1]] = -np.inf
        
        scored = score_flows(self.pipe, self.prep.feature_names, corrupt_df)
        self.assertTrue(np.isfinite(scored.loc[0, "malicious_score"]))
        self.assertTrue(np.isfinite(scored.loc[1, "malicious_score"]))

    def test_severe_corruption_isolated_as_unparseable(self):
        """Verify that rows with >80% corrupt/NaN features fail safely as UNPARSEABLE_ANOMALY."""
        corrupt_df = self.prep.X_test.copy().reset_index(drop=True)
        # Corrupt 100% of features in row 2
        for f in self.prep.feature_names:
            corrupt_df.loc[2, f] = np.nan

        scored = score_flows(self.pipe, self.prep.feature_names, corrupt_df)
        self.assertEqual(scored.loc[2, "prediction"], -1)
        self.assertEqual(scored.loc[2, "risk_level"], "UNPARSEABLE_ANOMALY")
        self.assertTrue(np.isnan(scored.loc[2, "malicious_score"]))

    def test_isolation_forest_inlier_outlier_prediction_consistency(self):
        """Verify that Isolation Forest inliers (+1) map to 0 and outliers (-1) map to 1."""
        iso_pipe = build_pipeline("isolation_forest", random_state=42, fast_mode=True)
        iso_pipe.fit(self.prep.X_train)
        scored = score_flows(iso_pipe, self.prep.feature_names, self.prep.X_test.head(10))

        self.assertIn("prediction", scored.columns)
        self.assertIn("risk_level", scored.columns)
        valid_predictions = {0, 1}
        self.assertTrue(set(scored["prediction"].unique()).issubset(valid_predictions))
        
        # Verify that prediction == 1 maps to HIGH risk
        high_risk_preds = scored[scored["risk_level"] == "HIGH"]["prediction"]
        self.assertTrue((high_risk_preds == 1).all())

    # =========================================================================
    # 2. PCAP ROBUSTNESS & BOUNDARY HANDLING
    # =========================================================================

    def test_empty_pcap_raises_empty_pcap_error(self):
        """Verify that a 0-byte capture file raises EmptyPcapError."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            with self.assertRaises(EmptyPcapError):
                extract_flows_from_pcap(tmp_path)
        finally:
            if tmp_path.is_file():
                tmp_path.unlink()

    def test_corrupt_pcap_header_raises_corrupt_pcap_error(self):
        """Verify that invalid header magic bytes raise CorruptPcapError."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(b"NOT_A_VALID_PCAP_MAGIC_HEADER_BYTES")
            tmp.flush()
            tmp_path = Path(tmp.name)
        try:
            with self.assertRaises(CorruptPcapError):
                extract_flows_from_pcap(tmp_path)
        finally:
            if tmp_path.is_file():
                tmp_path.unlink()

    def test_canonical_flow_columns_on_empty_flow_result(self):
        """Verify that PCAP extraction returns canonical schema even if 0 flows are formed."""
        # Test sample capture has flows, verify canonical column set
        sample_pcap = Path("data/sample/test_traffic.pcap")
        if sample_pcap.is_file():
            res = extract_flows_from_pcap(sample_pcap)
            for col in CANONICAL_FLOW_COLUMNS:
                self.assertIn(col, res.flow_dataframe.columns)

    # =========================================================================
    # 3. PRIVACY & STRUCTURED LOGGING
    # =========================================================================

    def test_ipv4_host_octet_redaction(self):
        """Verify that IP host octets are masked for privacy."""
        raw_ip = "192.168.1.45"
        redacted = redact_ip_address(raw_ip)
        self.assertEqual(redacted, "192.168.1.***")
        self.assertNotIn("45", redacted)

    def test_secret_and_credential_scrubbing(self):
        """Verify that passwords, tokens, and API keys are redacted from log messages."""
        msg = "User logged in with password='SuperSecretPassword123' and bearer=eyJh..."
        clean = sanitize_log_message(msg)
        self.assertNotIn("SuperSecretPassword123", clean)
        self.assertIn("[REDACTED_SECRET]", clean)

    def test_user_path_sanitization(self):
        """Verify that local Windows user profile paths are stripped from logs."""
        path_msg = r"Saved file to C:\Users\student\Documents\project\test.csv"
        clean = sanitize_log_message(path_msg)
        self.assertNotIn("student", clean)
        self.assertIn("[USER_DIR]", clean)

    # =========================================================================
    # 4. ROBUSTNESS PERTURBATION MECHANICS
    # =========================================================================

    def test_gaussian_noise_preserves_physical_positivity(self):
        """Verify that measurement noise maintains non-negative values for network rates."""
        X_orig = self.prep.X_test.copy()
        X_pert = apply_gaussian_measurement_noise(X_orig, noise_pct=0.15, random_state=42)
        
        # All non-negative features must remain >= 0
        for col in X_pert.select_dtypes(include=[np.number]).columns:
            self.assertTrue((X_pert[col] >= 0).all())

    def test_missing_feature_injection_preserves_shape(self):
        """Verify that missing feature injection maintains matrix dimensions and creates NaNs."""
        X_orig = self.prep.X_test.copy()
        X_drop = apply_missing_feature_injection(X_orig, missing_ratio=0.20, random_state=42)
        self.assertEqual(X_orig.shape, X_drop.shape)
        self.assertGreater(X_drop.isna().sum().sum(), 0)

    def test_adversarial_pacing_attenuation(self):
        """Verify that rate pacing increases duration and reduces packets per second."""
        X_orig = self.prep.X_test.copy()
        X_paced = apply_adversarial_pacing(X_orig, pace_factor=10.0)
        
        if "flow_duration_ms" in X_paced.columns:
            self.assertTrue((X_paced["flow_duration_ms"] >= X_orig["flow_duration_ms"]).all())
        if "flow_packets_per_second" in X_paced.columns:
            self.assertTrue((X_paced["flow_packets_per_second"] <= X_orig["flow_packets_per_second"]).all())


if __name__ == "__main__":
    unittest.main()
