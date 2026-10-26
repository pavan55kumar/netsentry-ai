"""Unit tests for NetSentry AI model factory and pipeline constructions."""
import unittest
from netsentry.models.factory import build_pipeline, get_available_models, list_available_keys
from netsentry.data.synthetic import make_demo_dataset
from netsentry.data.preprocessor import prepare_data
from netsentry.evaluation.metrics import calculate_inference_latency, measure_model_size_kb


class ModelFactoryTests(unittest.TestCase):
    def setUp(self):
        self.df = make_demo_dataset(rows=80, random_state=42)
        self.prep = prepare_data(self.df, "label", test_size=0.25, random_state=42)

    def test_all_models_can_be_built(self):
        """Verify all registered algorithms construct valid Pipelines."""
        keys = list_available_keys()
        self.assertGreaterEqual(len(keys), 9)
        for k in keys:
            pipe = build_pipeline(k, random_state=42, fast_mode=True)
            self.assertIsNotNone(pipe)
            self.assertIn("model", pipe.named_steps)

    def test_pipeline_fit_predict(self):
        """Verify standard algorithms fit without leakage and produce valid predictions."""
        for k in ["logistic_regression", "decision_tree", "random_forest_500", "k_nearest_neighbors"]:
            pipe = build_pipeline(k, random_state=42, fast_mode=True)
            pipe.fit(self.prep.X_train, self.prep.y_train)
            preds = pipe.predict(self.prep.X_test)
            self.assertEqual(len(preds), len(self.prep.X_test))

    def test_latency_and_size_measurement(self):
        """Verify operational engineering metrics are calculated correctly."""
        pipe = build_pipeline("logistic_regression", random_state=42)
        pipe.fit(self.prep.X_train, self.prep.y_train)
        lat = calculate_inference_latency(pipe, self.prep.X_test)
        size_kb = measure_model_size_kb(pipe)
        self.assertGreater(lat, 0.0)
        self.assertGreater(size_kb, 0.0)

    def test_lightgbm_and_xgboost_fit(self):
        """Verify LightGBM and XGBoost gradient boosters train and predict accurately."""
        for k in ["lightgbm", "xgboost"]:
            pipe = build_pipeline(k, random_state=42, fast_mode=True)
            pipe.fit(self.prep.X_train, self.prep.y_train)
            preds = pipe.predict(self.prep.X_test)
            self.assertEqual(len(preds), len(self.prep.X_test))


if __name__ == "__main__":
    unittest.main()

