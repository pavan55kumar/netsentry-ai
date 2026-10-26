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


if __name__ == "__main__":
    unittest.main()
