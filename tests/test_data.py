"""Unit tests for NetSentry AI data loading, validation, and splitting."""
import unittest
import numpy as np
import pandas as pd
from netsentry.data import (
    make_demo_dataset,
    prepare_data,
    detect_target_leakage,
    DeduplicationPolicy,
    SplitStrategy,
)


class DataTests(unittest.TestCase):
    def test_demo_split_is_binary_and_disjoint(self):
        """Preserve baseline test verifying synthetic dataset partitioning."""
        prepared = prepare_data(make_demo_dataset(rows=100, random_state=7), "label", random_state=7)
        self.assertEqual(set(prepared.y_train.unique()) | set(prepared.y_test.unique()), {0, 1})
        self.assertEqual(len(prepared.feature_names), 8)
        self.assertFalse(set(map(tuple, prepared.X_train.to_numpy())) & set(map(tuple, prepared.X_test.to_numpy())))

    def test_target_leakage_detection(self):
        """Verify that columns containing target, attack, or ID names are identified."""
        cols = ["flow_duration", "Total_Packets", "Attack_Category", "Flow ID", "target_class", "timestamp"]
        leaky = detect_target_leakage(cols, label_column="label")
        self.assertIn("Attack_Category", leaky)
        self.assertIn("Flow ID", leaky)
        self.assertIn("target_class", leaky)
        self.assertIn("timestamp", leaky)
        self.assertNotIn("flow_duration", leaky)
        self.assertNotIn("Total_Packets", leaky)

    def test_multiclass_preparation(self):
        """Verify multi-class dataset preparation preserves discrete attack categories."""
        df = pd.DataFrame({
            "feat_a": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
            "feat_b": [10.0, 20.0, 30.0, 40.0, 50.0, 60.0],
            "category": ["benign", "benign", "DoS", "DoS", "PortScan", "PortScan"],
        })
        prep = prepare_data(df, label_column="category", multiclass=True, test_size=0.33, random_state=42)
        self.assertTrue(prep.is_multiclass)
        self.assertEqual(len(prep.target_names), 3)
        self.assertEqual(prep.target_names[0], "benign")

    def test_temporal_splitting(self):
        """Verify that chronological splitting preserves arrival order."""
        df = pd.DataFrame({
            "timestamp": [10, 20, 30, 40, 50, 60, 70, 80],
            "pkt_rate": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0],
            "label": ["benign", "benign", "benign", "benign", "malicious", "malicious", "malicious", "malicious"],
        })
        prep = prepare_data(
            df,
            label_column="label",
            split_strategy=SplitStrategy.TEMPORAL,
            time_column="timestamp",
            test_size=0.25,
        )
        self.assertEqual(len(prep.X_train), 6)
        self.assertEqual(len(prep.X_test), 2)

    def test_invalid_schema_raises_error(self):
        """Verify that missing label column or absent numeric features raises ValueError."""
        df_no_label = pd.DataFrame({"f1": [1, 2], "f2": [3, 4]})
        with self.assertRaises(ValueError):
            prepare_data(df_no_label, label_column="non_existent")

        df_no_numeric = pd.DataFrame({"cat1": ["a", "b"], "cat2": ["x", "y"], "label": ["0", "1"]})
        with self.assertRaises(ValueError):
            prepare_data(df_no_numeric, label_column="label")

    def test_infinite_and_missing_value_handling(self):
        """Verify that infinite values (e.g. from 0-duration division) are safely handled."""
        df = pd.DataFrame({
            "flow_bytes_per_second": [100.0, np.inf, 300.0, -np.inf, 500.0, 600.0, 700.0, 800.0],
            "syn_flag_count": [1, 0, 1, 0, 1, 0, 1, 0],
            "label": ["benign", "benign", "benign", "benign", "malicious", "malicious", "malicious", "malicious"],
        })
        prep = prepare_data(df, label_column="label", test_size=0.25, random_state=42)
        # Infinite values should be replaced with NaN, and imputer inside pipeline will handle them
        self.assertFalse(np.isinf(prep.X_train.to_numpy()).any())
        self.assertFalse(np.isinf(prep.X_test.to_numpy()).any())


if __name__ == "__main__":
    unittest.main()
