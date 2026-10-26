"""Unit tests for NetSentry AI evaluation metrics, baseline check, and threshold calibration."""
import unittest
import numpy as np
from netsentry.evaluation.metrics import evaluate_predictions
from netsentry.evaluation.baseline import evaluate_majority_baseline
from netsentry.training.threshold import optimize_decision_threshold
from netsentry.models.factory import build_pipeline
from netsentry.data.synthetic import make_demo_dataset
from netsentry.data.preprocessor import prepare_data


class EvaluationTests(unittest.TestCase):
    def test_binary_metrics_calculation(self):
        y_true = np.array([0, 0, 1, 1, 0, 1])
        y_pred = np.array([0, 0, 1, 0, 0, 1])
        metrics = evaluate_predictions(y_true, y_pred)
        self.assertEqual(metrics.true_positives, 2)
        self.assertEqual(metrics.false_negatives, 1)
        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.false_positive_rate, 0.0)
        self.assertAlmostEqual(metrics.accuracy, 5 / 6)

    def test_majority_baseline_accuracy_trap(self):
        """Verify that majority dummy baseline reveals the Accuracy Trap."""
        y_train = np.array([0] * 90 + [1] * 10)
        y_test = np.array([0] * 90 + [1] * 10)
        baseline = evaluate_majority_baseline(y_train, y_test)
        m = baseline["baseline_metrics"]
        self.assertAlmostEqual(m["accuracy"], 0.90)
        self.assertEqual(m["recall_malicious"], 0.0)
        self.assertIn("accuracy alone is deceptive", baseline["accuracy_trap_explanation"])

    def test_threshold_optimization(self):
        df = make_demo_dataset(rows=120, random_state=42)
        prep = prepare_data(df, "label", test_size=0.25, random_state=42)
        pipe = build_pipeline("logistic_regression", random_state=42)
        pipe.fit(prep.X_train, prep.y_train)

        opt = optimize_decision_threshold(pipe, prep.X_test, prep.y_test)
        self.assertGreaterEqual(opt.optimal_threshold_f1, 0.05)
        self.assertLessEqual(opt.optimal_threshold_f1, 0.95)
        self.assertGreater(len(opt.threshold_curve), 50)


if __name__ == "__main__":
    unittest.main()
