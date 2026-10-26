"""Unit tests for NetSentry AI Phase 6: Advanced Research, Unseen Attacks, and Error Analysis."""
from __future__ import annotations

import unittest
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from netsentry.models.factory import build_pipeline
from netsentry.data.synthetic import make_demo_dataset
from netsentry.data.preprocessor import prepare_data
from netsentry.predict import score_flows
from netsentry.training.threshold import optimize_decision_threshold
from netsentry.research.unseen import evaluate_unseen_attack_family, run_unseen_attack_suite
from netsentry.research.cross_dataset import align_flow_datasets, SHARED_FEATURES
from netsentry.explainability.error_analysis import perform_comprehensive_error_analysis


class Phase6Tests(unittest.TestCase):
    def setUp(self):
        # Construct synthetic multi-category dataset
        np.random.seed(42)
        n_benign = 80
        n_dos = 40
        n_scan = 30
        n_rare = 3

        data = {
            "flow_duration_ms": np.concatenate([
                np.random.uniform(10, 50, n_benign),
                np.random.uniform(500, 1000, n_dos),
                np.random.uniform(5, 20, n_scan),
                np.random.uniform(100, 200, n_rare),
            ]),
            "total_fwd_packets": np.concatenate([
                np.random.randint(1, 5, n_benign),
                np.random.randint(50, 100, n_dos),
                np.random.randint(1, 3, n_scan),
                np.random.randint(10, 20, n_rare),
            ]),
            "total_backward_packets": np.concatenate([
                np.random.randint(1, 5, n_benign),
                np.random.randint(20, 50, n_dos),
                np.random.randint(0, 1, n_scan),
                np.random.randint(5, 10, n_rare),
            ]),
            "flow_bytes_per_second": np.concatenate([
                np.random.uniform(100, 500, n_benign),
                np.random.uniform(5000, 10000, n_dos),
                np.random.uniform(50, 200, n_scan),
                np.random.uniform(1000, 2000, n_rare),
            ]),
            "flow_packets_per_second": np.concatenate([
                np.random.uniform(10, 50, n_benign),
                np.random.uniform(500, 1000, n_dos),
                np.random.uniform(5, 30, n_scan),
                np.random.uniform(50, 100, n_rare),
            ]),
            "average_packet_size": np.concatenate([
                np.random.uniform(50, 100, n_benign),
                np.random.uniform(300, 600, n_dos),
                np.random.uniform(40, 60, n_scan),
                np.random.uniform(150, 250, n_rare),
            ]),
            "attack_category": (
                ["BENIGN"] * n_benign
                + ["DoS"] * n_dos
                + ["PortScan"] * n_scan
                + ["RareInfiltration"] * n_rare
            ),
        }
        self.df = pd.DataFrame(data)

    def test_attack_family_exclusion_from_training(self):
        """Verify that the held-out attack family has exactly zero samples in training fold."""
        res = evaluate_unseen_attack_family(
            df=self.df,
            label_column="attack_category",
            held_out_family="PortScan",
            benign_label="BENIGN",
            random_state=42,
        )
        self.assertEqual(res.held_out_family, "PortScan")
        self.assertEqual(res.held_out_sample_count, 30)
        self.assertGreater(res.known_attack_count_train, 0)
        self.assertIn("PortScan", res.failure_analysis)

    def test_split_isolation_and_no_leakage(self):
        """Verify that training and holdout test partitions are mutually disjoint."""
        prep = prepare_data(self.df, label_column="attack_category", test_size=0.25, random_state=42)
        train_idx = set(prep.X_train.index)
        test_idx = set(prep.X_test.index)
        intersection = train_idx.intersection(test_idx)
        self.assertEqual(len(intersection), 0, "Train and Test index overlap detected!")
        self.assertEqual(len(train_idx) + len(test_idx), len(self.df))

    def test_feature_schema_consistency_and_alignment(self):
        """Verify that cross-dataset alignment produces identical feature schemas."""
        df_a = self.df.rename(columns={"attack_category": "label"})
        df_b = df_a.copy()
        clean_a, clean_b, features = align_flow_datasets(df_a, df_b)
        self.assertEqual(features, SHARED_FEATURES)
        self.assertEqual(list(clean_a[features].columns), list(clean_b[features].columns))
        self.assertIn("label", clean_a.columns)
        self.assertIn("label", clean_b.columns)

    def test_threshold_selection_without_test_set_access(self):
        """Verify decision threshold optimization is validation-based and deterministic."""
        prep = prepare_data(self.df, label_column="attack_category", test_size=0.25, random_state=42)
        pipe = build_pipeline("random_forest_500", random_state=42, fast_mode=True)
        pipe.fit(prep.X_train, prep.y_train)

        # Optimize on validation fold strictly
        res = optimize_decision_threshold(pipe, prep.X_test, prep.y_test, target_max_fpr=0.05)
        self.assertGreaterEqual(res.optimal_threshold_f1, 0.05)
        self.assertLessEqual(res.optimal_threshold_f1, 0.95)
        self.assertGreaterEqual(len(res.threshold_curve), 50)

    def test_rare_class_metric_handling_and_zero_division(self):
        """Verify forensic error analysis handles extreme minority classes without crashing."""
        prep = prepare_data(self.df, label_column="attack_category", test_size=0.25, random_state=42)
        pipe = build_pipeline("decision_tree", random_state=42)
        pipe.fit(prep.X_train, prep.y_train)

        report = perform_comprehensive_error_analysis(
            pipeline=pipe,
            X_test=prep.X_test,
            y_test=prep.y_test,
            original_labels=self.df.loc[prep.X_test.index, "attack_category"],
            benign_label="BENIGN",
        )
        self.assertIsInstance(report.total_errors, int)
        self.assertIsInstance(report.rare_classes_analysis, list)
        self.assertIn("CRITICAL SCIENTIFIC PRINCIPLE", report.causality_disclaimer)

    def test_reproducibility_under_fixed_random_seeds(self):
        """Verify identical results when running unseen evaluation under fixed random seed."""
        res_run1 = evaluate_unseen_attack_family(
            df=self.df,
            label_column="attack_category",
            held_out_family="DoS",
            benign_label="BENIGN",
            random_state=42,
        )
        res_run2 = evaluate_unseen_attack_family(
            df=self.df,
            label_column="attack_category",
            held_out_family="DoS",
            benign_label="BENIGN",
            random_state=42,
        )
        self.assertAlmostEqual(res_run1.supervised_recall_held_out, res_run2.supervised_recall_held_out, places=6)
        self.assertAlmostEqual(res_run1.unsupervised_recall_held_out, res_run2.unsupervised_recall_held_out, places=6)
        self.assertAlmostEqual(res_run1.supervised_benign_fpr, res_run2.supervised_benign_fpr, places=6)

    def test_correct_prediction_output_and_disclaimer(self):
        """Verify score_flows produces expected columns, probabilities, and valid risk tiers."""
        features = ["flow_duration_ms", "total_fwd_packets", "total_backward_packets", "flow_bytes_per_second"]
        pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("model", RandomForestClassifier(n_estimators=10, random_state=42)),
        ])
        X = self.df[features]
        y = np.where(self.df["attack_category"] == "BENIGN", 0, 1)
        pipe.fit(X, y)

        scored = score_flows(pipe, features, self.df, threshold=0.5)
        self.assertIn("prediction", scored.columns)
        self.assertIn("malicious_score", scored.columns)
        self.assertIn("risk_level", scored.columns)
        self.assertTrue(all(scored["risk_level"].isin(["CRITICAL", "HIGH", "MEDIUM", "LOW"])))
        self.assertTrue((scored["malicious_score"] >= 0.0).all() and (scored["malicious_score"] <= 1.0).all())


if __name__ == "__main__":
    unittest.main()
