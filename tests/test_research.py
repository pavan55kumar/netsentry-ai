"""Unit tests for NetSentry AI advanced research modules."""
import unittest
from netsentry.models.factory import build_pipeline
from netsentry.data.synthetic import make_demo_dataset
from netsentry.data.preprocessor import prepare_data
from netsentry.research.anomaly import benchmark_unsupervised_anomaly
from netsentry.research.drift import simulate_model_drift


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.df = make_demo_dataset(rows=120, random_state=42)
        self.prep = prepare_data(self.df, "label", test_size=0.25, random_state=42)
        self.pipe = build_pipeline("random_forest_500", random_state=42, fast_mode=True)
        self.pipe.fit(self.prep.X_train, self.prep.y_train)

    def test_unsupervised_anomaly_benchmark(self):
        res = benchmark_unsupervised_anomaly(
            self.prep.X_train, self.prep.X_test, self.prep.y_train, self.prep.y_test
        )
        self.assertGreaterEqual(res.zero_day_detection_rate, 0.0)
        self.assertGreaterEqual(res.benign_false_alarm_rate, 0.0)
        self.assertEqual(len(res.educational_insights), 3)

    def test_model_drift_simulation(self):
        res = simulate_model_drift(
            self.pipe, self.prep.X_test, self.prep.y_test, drift_type="volumetric_spike", intensities=[0.0, 0.5, 1.0]
        )
        self.assertEqual(len(res.macro_f1_scores), 3)
        self.assertIn("Simulated Volumetric Spike", res.analysis)

    def test_unseen_attack_detection(self):
        from netsentry.research.anomaly import evaluate_unseen_attack_detection
        import pandas as pd
        df = pd.DataFrame({
            "f1": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 50.0, 55.0],
            "f2": [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0, 500.0, 550.0],
            "attack": ["benign"] * 6 + ["DoS"] * 4 + ["ZeroDayScan"] * 2,
        })
        res = evaluate_unseen_attack_detection(df, label_column="attack", held_out_attack="ZeroDayScan", benign_label="benign")
        self.assertEqual(res.held_out_attack, "ZeroDayScan")
        self.assertEqual(res.total_unseen_samples, 2)
        self.assertIn("Zero-Day Simulation", res.findings)

    def test_cross_dataset_and_joint_domain_generalization(self):
        from netsentry.research.cross_dataset import evaluate_cross_dataset, evaluate_joint_domain_generalization
        import pandas as pd
        df_a = pd.DataFrame({
            "flow_duration_ms": [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0],
            "total_fwd_packets": [1, 2, 1, 2, 10, 20, 15, 25],
            "total_backward_packets": [1, 1, 1, 1, 5, 10, 8, 12],
            "flow_bytes_per_second": [100.0, 200.0, 150.0, 250.0, 5000.0, 8000.0, 6000.0, 9000.0],
            "flow_packets_per_second": [10.0, 15.0, 12.0, 18.0, 500.0, 800.0, 600.0, 900.0],
            "average_packet_size": [50.0, 60.0, 55.0, 65.0, 300.0, 400.0, 350.0, 450.0],
            "label": ["benign", "benign", "benign", "benign", "DoS", "DoS", "DoS", "DoS"],
        })
        df_b = df_a.copy()
        res_cross = evaluate_cross_dataset(df_a, df_b, source_name="DemoA", target_name="DemoB")
        self.assertGreaterEqual(res_cross.in_domain_metrics.f1_macro, 0.0)
        self.assertGreaterEqual(res_cross.cross_domain_metrics.f1_macro, 0.0)

        res_joint = evaluate_joint_domain_generalization(df_a, df_b, name_a="DemoA", name_b="DemoB")
        self.assertGreaterEqual(res_joint.test_a_metrics.f1_macro, 0.0)
        self.assertGreaterEqual(res_joint.test_b_metrics.f1_macro, 0.0)


if __name__ == "__main__":
    unittest.main()

