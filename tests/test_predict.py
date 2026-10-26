"""Unit tests for NetSentry AI prediction and risk tier scoring."""
import unittest
from netsentry.models.factory import build_pipeline
from netsentry.data.synthetic import make_demo_dataset
from netsentry.data.preprocessor import prepare_data
from netsentry.predict import score_flows


class PredictTests(unittest.TestCase):
    def test_score_flows_and_risk_assignment(self):
        df = make_demo_dataset(rows=80, random_state=42)
        prep = prepare_data(df, "label", test_size=0.25, random_state=42)
        pipe = build_pipeline("random_forest_500", random_state=42, fast_mode=True)
        pipe.fit(prep.X_train, prep.y_train)

        scored = score_flows(pipe, prep.feature_names, prep.X_test)
        self.assertIn("prediction", scored.columns)
        self.assertIn("risk_level", scored.columns)
        self.assertIn("malicious_score", scored.columns)
        self.assertEqual(len(scored), len(prep.X_test))
        valid_tiers = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        self.assertTrue(set(scored["risk_level"].unique()).issubset(valid_tiers))


if __name__ == "__main__":
    unittest.main()
