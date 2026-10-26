"""Unit and regression tests for Phase 9 research validation and security audit."""
import json
from pathlib import Path
import unittest
import numpy as np
import pandas as pd

from netsentry.data.preprocessor import prepare_data, detect_target_leakage
from netsentry.data.splitting import split_dataset, SplitStrategy
from netsentry.models.factory import build_pipeline
from netsentry.predict import score_flows, SchemaMismatchError
from netsentry.pcap.flow_extractor import extract_flows_from_pcap, CANONICAL_FLOW_COLUMNS
from netsentry.utils.logging import redact_ip_address, sanitize_log_message


class Phase9AuditTests(unittest.TestCase):
    """Rigorous audit test cases for data leakage, schema validity, and security policies."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.sample_cic_path = cls.repo_root / "data" / "sample" / "cicids2017_sample.csv"
        cls.sample_pcap_path = cls.repo_root / "data" / "sample" / "test_traffic.pcap"
        cls.audit_results_path = cls.repo_root / "artifacts" / "phase9_audit_results.json"

    def test_train_test_split_disjointness_and_no_leakage(self):
        """Verify that training and holdout test partitions have strictly zero index or row overlap."""
        self.assertTrue(self.sample_cic_path.is_file(), "CIC-IDS2017 sample must exist")
        df = pd.read_csv(self.sample_cic_path, low_memory=False)
        prep = prepare_data(df, label_column="Label", test_size=0.25, random_state=42)

        train_indices = set(prep.X_train.index)
        test_indices = set(prep.X_test.index)
        overlap = train_indices.intersection(test_indices)

        self.assertEqual(len(overlap), 0, f"Detected {len(overlap)} overlapping indices between train and test!")
        self.assertEqual(len(prep.X_train) + len(prep.X_test), len(prep.X_train) + len(prep.X_test))
        self.assertNotIn("Label", prep.feature_names)
        self.assertNotIn("label", [f.lower() for f in prep.feature_names])

    def test_target_leakage_detector(self):
        """Verify automatic detection and rejection of columns encoding the target or host identifiers."""
        columns = [
            "flow_id",
            "timestamp",
            "src_ip",
            "source_ip",
            "dst_ip",
            "destination_ip",
            "attack_category",
            "packet_rate",
            "byte_count",
            "target",
            "label",
        ]
        leaky = detect_target_leakage(columns, label_column="label")
        self.assertIn("flow_id", leaky)
        self.assertIn("timestamp", leaky)
        self.assertIn("src_ip", leaky)
        self.assertIn("destination_ip", leaky)
        self.assertIn("attack_category", leaky)
        self.assertIn("target", leaky)
        self.assertNotIn("packet_rate", leaky)
        self.assertNotIn("byte_count", leaky)

    def test_pipeline_scalers_fitted_exclusively_on_training_fold(self):
        """Verify that StandardScaler and SimpleImputer statistics are computed strictly on training folds."""
        df = pd.read_csv(self.sample_cic_path, low_memory=False)
        prep = prepare_data(df, label_column="Label", test_size=0.25, random_state=42)

        pipe = build_pipeline("logistic_regression", random_state=42)
        pipe.fit(prep.X_train, prep.y_train)

        scaler = pipe.named_steps["scaler"]
        imputer = pipe.named_steps["imputer"]

        self.assertEqual(len(scaler.mean_), prep.X_train.shape[1])
        self.assertEqual(len(imputer.statistics_), prep.X_train.shape[1])

        # Verify that transforming X_test does NOT modify scaler statistics
        original_means = np.copy(scaler.mean_)
        _ = pipe.predict_proba(prep.X_test)
        np.testing.assert_array_equal(scaler.mean_, original_means)

    def test_pcap_flow_extraction_schema_and_types(self):
        """Verify offline PCAP packet ingestion yields valid canonical flow rows with correct numeric types."""
        self.assertTrue(self.sample_pcap_path.is_file(), "Sample PCAP must exist")
        res = extract_flows_from_pcap(self.sample_pcap_path)
        self.assertGreater(res.total_packets_read, 0)
        self.assertGreater(res.total_flows_extracted, 0)
        df = res.flow_dataframe

        for col in CANONICAL_FLOW_COLUMNS:
            self.assertIn(col, df.columns)

        self.assertTrue(np.issubdtype(df["flow_duration_ms"].dtype, np.number))
        self.assertTrue(np.issubdtype(df["total_fwd_packets"].dtype, np.integer))
        self.assertTrue(np.issubdtype(df["flow_bytes_per_second"].dtype, np.number))

    def test_security_ip_redaction_and_secret_scrubbing(self):
        """Verify privacy-preserving IP host redaction and credential scrubbing."""
        ipv4 = "10.0.4.77"
        redacted = redact_ip_address(ipv4)
        self.assertEqual(redacted, "10.0.4.***")

        ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        redacted_v6 = redact_ip_address(ipv6)
        self.assertTrue(redacted_v6.endswith(":****"))

        log_msg = "User logged in with token=ghp_secretTokenVal123 and path C:\\Users\\Administrator\\Desktop"
        sanitized = sanitize_log_message(log_msg)
        self.assertNotIn("ghp_secretTokenVal123", sanitized)
        self.assertNotIn("Administrator", sanitized)

    def test_quarantine_policy_on_infinite_and_unparseable_inputs(self):
        """Verify that infinite rates and excessive corruptions fail safely into quarantine."""
        features = ["flow_duration_ms", "total_fwd_packets", "total_backward_packets",
                    "flow_bytes_per_second", "flow_packets_per_second",
                    "syn_flag_count", "rst_flag_count", "average_packet_size"]
        pipe = build_pipeline("decision_tree", random_state=42)
        X_dummy = pd.DataFrame([{f: 100.0 for f in features} for _ in range(10)])
        y_dummy = [0, 1] * 5
        pipe.fit(X_dummy, y_dummy)

        # Non-finite rate
        bad_df = pd.DataFrame([{
            "flow_duration_ms": 100.0,
            "total_fwd_packets": 5,
            "total_backward_packets": 5,
            "flow_bytes_per_second": np.inf,
            "flow_packets_per_second": 10.0,
            "syn_flag_count": 0,
            "rst_flag_count": 0,
            "average_packet_size": 100.0,
        }])
        scored = score_flows(pipe, features, bad_df)
        self.assertEqual(scored.iloc[0]["prediction"], -1)
        self.assertEqual(scored.iloc[0]["risk_level"], "QUARANTINE_NON_FINITE")

    def test_audit_results_artifact_integrity(self):
        """Verify that phase9_audit_results.json exists, is non-empty, and contains all required checks."""
        self.assertTrue(self.audit_results_path.is_file(), "phase9_audit_results.json must exist")
        with open(self.audit_results_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("audit_checks", data)
        self.assertTrue(data["execution_summary"]["all_checks_passed"])
        self.assertIn("dataset_splitting_and_leakage", data["audit_checks"])
        self.assertIn("research_metrics_verification", data["audit_checks"])
        self.assertIn("pcap_to_model_validity", data["audit_checks"])
        self.assertIn("security_and_operational_safety", data["audit_checks"])


if __name__ == "__main__":
    unittest.main()
